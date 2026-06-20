# Cloudflare MCP Client Contract

This document is the client-facing request contract for `cloudflare-mcp`: what to send, what is required, and what safety headers to include.

Related docs:
- `../README.md` for setup/auth/systemd/Codex wiring.
- `./RUNBOOK.md` for phased rollout and rollback sequencing.

## Protocol and endpoint requirements

- Transport: MCP Streamable HTTP.
- MCP endpoint: `POST|GET|DELETE /mcp`.
- `/mcp/` is accepted and normalized to `/mcp`.
- Public endpoints (no auth by policy): `GET /health`, `GET /attest`.

## Required headers and envelope

| Item | Required | Notes |
| --- | --- | --- |
| `Host` | Yes | Host value (port is allowed) must match `CLOUDFLARE_MCP_ALLOWED_HOSTS` host allowlist. |
| `Content-Type: application/json` | Yes for `POST /mcp` | Required for JSON-RPC requests. |
| `Authorization: Bearer <token>` | Required when auth is enabled | Auth is enabled unless `CLOUDFLARE_MCP_AUTH_MODE=off` (or optional loopback mode is active). |
| `x-cloudflare-api-token` (or configured name) | Required only when upstream token source is header-based | Required when `CLOUDFLARE_MCP_API_TOKEN_SOURCE=header`; optional override when `header_or_config`. Header name is configurable via `CLOUDFLARE_MCP_API_TOKEN_HEADER`. |
| `Mcp-Session-Id` | Required after `initialize` for stateful requests | Use session ID returned by server response headers. |
| `Last-Event-Id` | Optional | Used for resume attempts; server uses historyless resume behavior when enabled. |
| `x-correlation-id` | Strongly recommended for mutating calls | Passed through to mutation `audit.correlation.correlation_id`. |
| `x-request-id` | Optional | Captured in mutation audit and used as correlation fallback if `x-correlation-id` is absent. |
| MCP `elicitation/create` handling | Required only when server-side elicitation gate is enabled | Client must support interactive approval responses for configured dangerous tools. |

JSON-RPC envelope shape:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "health",
    "arguments": {}
  }
}
```

## Session behavior

- First call should be `initialize` as `POST /mcp` with no session header.
- For later calls, include `Mcp-Session-Id`.
- If `CLOUDFLARE_MCP_HTTP_STATELESS_FALLBACK=true` (default), non-session POST calls can be handled statelessly.
- GET/DELETE calls without `Mcp-Session-Id` fail with `400`.
- Unknown or expired sessions fail with `404`; re-run `initialize`.

## Authentication behavior

- Supported auth modes: `delegation` (default), `resource_server`, `jwks`, `introspection`, `off`.
- Non-loopback bind requires auth enabled.
- `resource_server` mode requires `CLOUDFLARE_MCP_AUTH_ISSUER` and performs OIDC discovery at
  startup to hydrate missing issuer/JWKS metadata for inbound bearer validation. It only uses
  introspection when an introspection endpoint is explicitly configured together with the required
  client credentials. This is the recommended interactive OAuth mode for Codex and other
  browser-login clients.
- `delegation` mode requires `CLOUDFLARE_MCP_AUTH_DELEGATION_SECRET` unless
  loopback-only local development explicitly enables
  `CLOUDFLARE_MCP_AUTH_ALLOW_INSECURE_DEV_DELEGATION_SECRET=1`. Delegation is an
  delegated-token mode, not a self-hosted end-user login flow.
- Required token scopes default to `cloudflare:read,cloudflare:write` and can be overridden with `CLOUDFLARE_MCP_AUTH_REQUIRED_SCOPES`.
- Cloudflare upstream API credentials are independent from MCP bearer auth:
  set `CLOUDFLARE_MCP_API_TOKEN_SOURCE` to `config`, `header`, or `header_or_config`.
- R2 object reads use independent S3-compatible R2 credentials:
  set `CLOUDFLARE_MCP_R2_ACCESS_KEY_ID` and `CLOUDFLARE_MCP_R2_SECRET_ACCESS_KEY`,
  or their `_FILE` variants. `CLOUDFLARE_MCP_R2_ENDPOINT` is optional and
  defaults to `https://<account_id>.r2.cloudflarestorage.com`.

## Optional elicitation behavior

When `CLOUDFLARE_MCP_ELICITATION_ENABLED=1`:

- the server may issue MCP `elicitation/create` requests before configured dangerous tool calls,
- configured tool list comes from `CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS`,
- `account_api_tokens` and `api_mutate` are mandatory-gated while elicitation is enabled, even if omitted from that CSV,
- `account_api_tokens` read actions (`list_permission_groups`, `list`, `get`, `verify`) are treated as read-only for elicitation and do not prompt,
- with default `CLOUDFLARE_MCP_ELICITATION_APPLY_ONLY=1`, `dry_run=true` calls skip approval,
- decline/cancel/no-content responses deny the tool call (fail closed),
- clients without elicitation capability are denied unless `CLOUDFLARE_MCP_ELICITATION_FAIL_OPEN_UNSUPPORTED_CLIENT=1`,
- approval prompts time out after `CLOUDFLARE_MCP_ELICITATION_TIMEOUT_MS` (default `30000`; `0` disables timeout),
- server startup fails fast if required tools are unknown/non-mutating, or empty while elicitation is enabled.

## Common argument resolution rules

- `account_id` is required for account-scoped tools unless `CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID` is configured.
- `zone_id` is required for zone-scoped tools unless `CLOUDFLARE_MCP_DEFAULT_ZONE_ID` is configured.
- Missing required IDs return invalid params errors.
- Tool names are intentionally short and do not include a `cloudflare.` prefix;
  the MCP server label already provides that namespace in clients.

## Deferred loading

OpenAI Responses API clients can use tool search with GPT-5.4 and later; use
`gpt-5.5` as the current flagship target for complex operator workflows. To
defer this large MCP catalog, set `defer_loading: true` on the MCP tool
definition and include `{ "type": "tool_search" }` in the same `tools` array.
OpenAI hosted `tool_search` is a client-side Responses API feature: the server
continues to expose the same strict inventory through `tools/list` when the
client asks for it. Non-hosted clients can call `find_tools` to produce a
narrow `openai_allowed_tools` list and optional MCP schemas, then use that list
as the Responses `allowed_tools` value for a follow-up request.

```json
[
  {
    "type": "mcp",
    "server_label": "cloudflare",
    "server_description": "Self-hosted Cloudflare operator workflows: Tunnel, DNS, Access, Pages, D1, R2, Workers, Queues, WAF, Email Routing, cache, guarded publish, dry-run planning, approval gates, and readback verification.",
    "server_url": "https://<host>/mcp",
    "defer_loading": true
  },
  {
    "type": "tool_search"
  }
]
```

Leave `require_approval` unset for the safest default so OpenAI requests
approval before sharing tool-call data with the remote MCP server. If the
server and workflow are trusted, only bypass approval for reviewed read-only
tools; keep mutating tools approval-gated unless another workflow-level review
gate applies. The resource `cloudflare-mcp://openai/tool-search-config`
contains the current template plus a read-only-only optional approval override.

## Tool argument contract

| Tool | Required arguments | Optional arguments | Notes |
| --- | --- | --- | --- |
| `health` | none | none | Runtime status summary. |
| `find_tools` | none | `query`, `group`, `read_only`, `limit`, `include_schema` | Searches local tool metadata for non-hosted deferred-loading clients and returns `openai_allowed_tools`; with `include_schema=true`, returns MCP tool objects keyed by tool name. Hosted OpenAI `tool_search` does not call this tool automatically. |
| `api_parity_status` | none | none | Summarizes the committed Cloudflare REST API v4 catalog and generic executor coverage. |
| `api_find_operations` | none | `query`, `tag`, `method`, `scope`, `risk`, `include_deprecated`, `limit` | Searches the official OpenAPI-derived operation catalog. |
| `api_get_operation` | `operation_id` | none | Shows parameters, risk, call template, executor, and preferred curated tool when one exists. |
| `api_prepare_call` | `operation_id` or enough search filters | `query`, `tag`, `method`, `scope`, `risk`, `include_deprecated`, `path_params`, `query_params`, `body`, `limit` | Resolves an operation and returns exact `api_read`/`api_mutate` arguments. Ambiguous searches return candidates instead of guessing; mutating operations are prepared as `dry_run=true`. Path parameters are derived from the URL template as well as catalog metadata, so stale catalog `path_params` cannot leave literal `{account_id}` placeholders in prepared paths. The returned `resolved_path_params` and `call.arguments.path_params` include configured account/zone defaults, making the prepared call self-contained. |
| `api_read` | `operation_id` | `path_params`, `query`, `max_bytes` | Executes catalog `GET` operations only; uses configured account/zone defaults for matching path params. Path parameters are derived from the URL template as well as catalog metadata. |
| `api_mutate` | `operation_id` | `path_params`, `query`, `body`, `dry_run`, `confirmation_token`, `reason` | Executes catalog `POST`/`PUT`/`PATCH`/`DELETE` operations through dry-run confirmation; high-risk denied operations fail closed. Valid escaped JSON-string `body` values are normalized into real JSON and reported with `body_normalized_from_json_string`. |
| `account_billing_usage` | none if default account configured | `account_id`, `mode`, `from`, `to`, `metric`, `max_bytes` | Read-only account usage helper for billing investigations. `mode=paygo` calls `/accounts/{account_id}/paygo-usage`; `mode=billable_usage` calls `/accounts/{account_id}/billable/usage` and requires `metric`. Use this for billable usage records before using analytics to explain attribution. |
| `graphql_analytics_query` | `query` | `variables`, `max_bytes` | Runs a read-only Cloudflare Analytics GraphQL query against `/client/v4/graphql`. Mutations and subscriptions are rejected before HTTP. Use this for product analytics such as D1 `d1AnalyticsAdaptiveGroups` and `d1QueriesAdaptiveGroups`; Cloudflare documents GraphQL analytics as attribution/analytics data, not a billing-record replacement. |
| `waf_ruleset_summary` | none if default zone or account configured | `account_id`, `zone_id`, `scope`, `phases`, `include_rules`, `include_raw`, `max_bytes` | Reads WAF Ruleset Engine entrypoints for custom rules, managed rules, and rate limiting rules. `scope=auto` prefers zone scope, then account scope. `phases` accepts aliases such as `custom`, `managed`, and `ratelimit`; defaults to `http_request_firewall_custom`, `http_request_firewall_managed`, and `http_ratelimit`. |
| `waf_security_events_summary` | `zone_id` unless default zone configured | `window_hours`, `since`, `until`, `group_by`, `action`, `source`, `host`, `path`, `client_ip`, `rule_id`, `limit`, `sample_limit`, `include_query`, `max_bytes` | Runs a curated read-only Cloudflare Analytics GraphQL query over the Security Events dataset `firewallEventsAdaptive`. Defaults to a 24-hour window, grouped by action/source/host/path/country/hour, with recent samples. |
| `waf_rule_activity` | `rule_id`; `zone_id` unless default zone configured for analytics | `account_id`, `zone_id`, `scope`, `phases`, `window_hours`, `since`, `until`, `sample_limit`, `include_query`, `include_raw`, `max_bytes` | Finds a WAF rule in current Rulesets and queries recent Security Events for the same rule ID. For account-scoped ruleset lookup, still provide `zone_id` for the zone-scoped `firewallEventsAdaptive` dataset. |
| `account_api_tokens` | `action`; `account_id` unless default account configured | `token_id`, `query`, `body`, `dry_run`, `confirmation_token`, `reason`, `max_bytes` | Curated account API token management. Read actions do not prompt under elicitation; mutating actions use dry-run confirmation and audit metadata. |
| `account_api_token_permission_plan` | `token_id` or `current_token`; `account_id` unless default account configured | `policy_index`, `add_permissions`, `remove_permissions`, `permission_groups`, `include_catalog`, `reason`, `max_bytes`; aliases `add`, `add_scopes`, `remove`, `remove_scopes` | Read-only permission delta planner for existing account API tokens. Fetches or accepts current token details and permission groups, resolves permission group ids/names/exact scopes, preserves existing policy permissions unless explicitly removed, and returns the exact `account_api_tokens action=update dry_run=true` payload. For multi-policy tokens, requires explicit `policy_index`. |
| `capabilities_check` | `account_id` and `zone_id` unless defaults configured | none | Checks whether configured credentials can reach representative account and zone APIs. |
| `list_tunnels` | `account_id` unless default account configured | `page`, `per_page` | `per_page` is clamped to `1..100`; default `50`. |
| `ensure_tunnel` | `tunnel_name`; `account_id` unless default account configured | `dry_run` | `tunnel_name` must be non-empty. |
| `generate_tunnel_ingress` | `tunnel_id`, `tunnel_name`, `rules[]` | none | Rules may be objects or shorthand strings; service-only rules become catch-all entries. Rule order is preserved. |
| `connector_control` | `connector_key`, `action` | `dry_run` | `action` must be `start`, `stop`, or `restart`. |
| `list_dns_records` | `zone_id` unless default zone configured | `hostname` | Lists CNAME records, optional hostname filter. |
| `d1_list_databases` | `account_id` unless default account configured | `name`, `page`, `per_page` | Curated read-only D1 database listing; prefer this over generic API parity for D1 discovery. |
| `d1_get_database` | `database_id`; `account_id` unless default account configured | none | Curated read-only D1 database metadata lookup. |
| `d1_rename_database` | `database_id`, `name`; `account_id` unless default account configured | `dry_run` | Curated D1 database rename via Cloudflare's partial-update endpoint. Dry-run returns the planned PATCH without applying it. |
| `d1_delete_database` | `database_id`; `account_id` unless default account configured | `dry_run`, `confirmation_token`, `reason` | Curated high-risk D1 database delete. Run with `dry_run=true` first and pass the emitted `required_confirmation_token` to live apply. |
| `d1_inspect_schema` | `database_id`; `account_id` unless default account configured | `include_columns`, `include_tables`, `include_table_pattern` | Curated D1 schema inspection using Cloudflare-compatible `sqlite_master`/PRAGMA read-only queries. `include_tables` is an exact-name allowlist and `include_table_pattern` is a simple `*`/`?` glob, both applied before column PRAGMAs. Cloudflare internal `_cf_*` objects are returned under `skipped_internal_tables` instead of `column_errors`; `summary.message` states whether application schema was returned, internal tables were skipped, or no application tables matched. If D1 denies an application table/view column PRAGMA, the tool still returns schema objects plus readable columns and reports `column_errors`/`column_discovery_fidelity`. View columns are marked with `object_type=view` and `derived=true`. Does not require Wrangler. |
| `d1_query_read_only` | `database_id`, `sql`; `account_id` unless default account configured | `params`, `max_rows` | Curated Cloudflare D1 SQL read/execute path for returning rows from read-only SELECT/query statements. SQL is checked by the shared restricted-SQL classifier before Cloudflare is contacted; catalog discovery reads fall back to the schema-inspection path when D1 returns `SQLITE_AUTH`. A `no such column` failure returns `d1.no_such_column`, and a `no such table` failure returns `d1.no_such_table`, with guidance to run `d1_validate_query` on the exact SQL or inspect only the suspected table/view with `d1_inspect_schema` include filters rather than sweeping the full database schema. |
| `d1_validate_query` | `database_id`, `sql`; `account_id` unless default account configured | `include_query_plan` | Validates one read-only D1 SQL statement against application schema metadata without executing that statement. Returns distinct `not_allowed`, `not_application_schema`, and `column_does_not_exist` style failures; the SQL reference parser reports function calls separately from column references so expressions such as `coalesce(...)`, `toDateTime(...)`, and aggregate helpers do not become false missing-column errors. When requested and validation passes, fetches `EXPLAIN QUERY PLAN` as plan metadata without running the user query. |
| `d1_execute_write` | `database_id`, `sql`; `account_id` unless default account configured | `params`, `dry_run`, `max_rows` | Executes one audited D1 row-write statement after dry-run planning. Allows only single-statement `INSERT`, `UPDATE`, `DELETE`, or `REPLACE`; schema-changing migration SQL belongs in `d1_apply_migrations`. |
| `d1_apply_migrations` | `database_id`, `migrations_directory`; `account_id` unless default account configured | `migrations_table`, `dry_run`, `max_rows` | Applies Wrangler-style `.sql` D1 migrations. Defaults to Wrangler's `d1_migrations` ledger table, reads `SELECT * FROM "<table>" ORDER BY id`, skips exact filename matches already in the ledger, and applies only pending files in Wrangler-compatible order with a ledger insert appended to each migration. `dry_run=true` performs remote ledger readback without writes and returns `already_applied`, `skipped_migrations`, `pending_migrations`, and `unknown_ledger`; if the ledger cannot be read, the tool fails closed before executing migration SQL. |
| `analytics_engine_list_datasets` | `account_id` unless default account configured | `max_rows` | Lists Workers Analytics Engine datasets by running `SHOW TABLES` through Cloudflare's Analytics Engine SQL API. The SQL API response is returned in its native `FORMAT JSON` shape. Requires an upstream token with Account Analytics Read permission. |
| `analytics_engine_query` | `sql`; `account_id` unless default account configured | `max_rows` | Runs one read-only Workers Analytics Engine SQL statement after the shared restricted-SQL classifier approves it. The SQL is sent as raw text to `/accounts/{account_id}/analytics_engine/sql`, and the SQL API response is decoded in its native `FORMAT JSON` shape rather than the standard Cloudflare v4 envelope. |
| `analytics_engine_describe_schema` | `account_id` unless default account configured | `max_rows` | Lists Analytics Engine datasets with `SHOW TABLES` and returns documented schema/version hints for `dataset`, `timestamp`, `_sample_interval`, `index1`, `blob1`-`blob20`, and `double1`-`double20`, including blob/double/index mapping guidance. |
| `analytics_engine_validate_query` | `sql`; `account_id` unless default account configured | `include_dataset_readback` | Validates one read-only Analytics Engine SQL statement against dataset readback and documented column schema hints without executing that statement. Returns missing dataset and missing column errors separately, reports function calls separately from column references, and includes explicit metadata that the SQL API does not expose a pre-execution query plan. |
| `r2_get_object` | `bucket_name`, `object_key`; `account_id` unless default account configured | `range`, `max_bytes`, `response_mode`, `output_path`, `persist_output_path`, `create_parent_dirs`, `allow_large_download` | Signed private R2 object read/download. `response_mode` is `auto` (default), `text`, `base64`, or `file`. Inline responses are preview-sized (`max_bytes` defaults to 1 KiB and is capped at 256 KiB). `response_mode=file` streams the object directly to `output_path` and returns `bytes_written`, `sha256`, `content_type`, `etag`, and `last_modified`; parent directories are created only when `create_parent_dirs=true`. Set `persist_output_path=true` with `output_path` to save that path locally for future file downloads; the state file defaults to `$XDG_STATE_HOME/cloudflare-mcp/r2-output-path.json` or `$HOME/.local/state/cloudflare-mcp/r2-output-path.json`, and can be overridden with `CLOUDFLARE_MCP_R2_OUTPUT_PATH_STATE_FILE`. `auto` returns inline text only for small UTF-8 objects; binary objects and oversized objects switch to file when an argument or persisted `output_path` is available, otherwise they fail closed with a hint rather than flooding the tool response. Local file downloads over the default large-object threshold require `allow_large_download=true`, `max_bytes`, or `range`. |
| `r2_inspect_object` | `bucket_name`, `object_key`; `account_id` unless default account configured | none | Signed private R2 object metadata inspection using `HEAD`; does not download the object body. |
| `r2_put_object` | `bucket_name`, `object_key`; `account_id` unless default account configured; one of `content_text` or `content_base64` | `content_type`, `metadata`, `dry_run` | Signed private R2 object write using `PUT`; `metadata` maps to `x-amz-meta-*` headers. |
| `pages_deploy_directory` | `project_name`, `directory`; `account_id` unless default account configured | `project_root`, `branch`, `commit_hash`, `commit_message`, `commit_dirty`, `skip_caching`, `dry_run`, `max_files` | Direct-uploads a local Pages output directory. Live apply obtains an upload token, uploads missing assets, sends the required multipart `manifest`, and returns upload counts plus the deployment. `_headers`, `_redirects`, advanced-mode `_worker.js`, and Wrangler-generated multipart `_worker.bundle` are supported. For Pages projects with a sibling or ancestor `functions/` directory, the tool runs Wrangler's Pages Functions build with an `_worker.bundle` outfile, includes Wrangler's generated bundle and `functions-filepath-routing-config.json`, and reports `directory.functions.detected`/`included` during dry-run and live apply. Use `project_root` when the build output directory is not inside the Pages project root. `_routes.json` is accepted only when the same artifact includes `_worker.js`, `_worker.bundle`, or a successfully bundled Pages Functions payload; otherwise it fails closed as `pages.routes_without_worker`. A multipart bundle accidentally named `_worker.js` fails closed as `pages.worker_js_contains_multipart_bundle` to avoid Cloudflare parsing a form boundary as JavaScript. If the deployment directory itself contains `functions/`, the tool fails closed as `pages.functions_inside_output_directory`; provide the static output directory such as `dist` instead. |
| `pages_trigger_deployment` | `project_name`; `account_id` unless default account configured | `branch`, `commit_hash`, `commit_message`, `commit_dirty`, `dry_run` | Triggers Git-backed Pages projects only. Direct-upload projects should use `pages_deploy_directory`; manifest-required Cloudflare errors are normalized to a Pages-specific MCP error. |
| `pages_list_projects` | `account_id` unless default account configured | `page`, `per_page` | Lists Pages projects for the account. |
| `pages_get_project` | `project_name`; `account_id` unless default account configured | none | Reads one Pages project. |
| `pages_update_project` | `project_name`, `settings`; `account_id` unless default account configured | `dry_run` | Updates Pages project settings through a guarded dry-run/apply path. |
| `pages_list_deployments` | `project_name`; `account_id` unless default account configured | `environment`, `page`, `per_page` | Lists deployments for a Pages project. |
| `pages_get_deployment` | `project_name`, `deployment_id`; `account_id` unless default account configured | none | Reads one Pages deployment. |
| `pages_retry_deployment` | `project_name`, `deployment_id`; `account_id` unless default account configured | `dry_run` | Retries a Pages deployment through a guarded action path. |
| `pages_rollback_deployment` | `project_name`, `deployment_id`; `account_id` unless default account configured | `dry_run` | Rolls production back to a previous Pages deployment through a guarded action path. |
| `pages_list_domains` | `project_name`; `account_id` unless default account configured | none | Lists custom domains attached to a Pages project. |
| `pages_get_domain` | `project_name`, `domain_name`; `account_id` unless default account configured | none | Reads one Pages custom domain. |
| `pages_ensure_domain` | `project_name`, `domain_name`; `account_id` unless default account configured | `dry_run` | Ensures a Pages custom domain exists; dry-run returns the planned create/readback flow. |
| `pages_retry_domain_validation` | `project_name`, `domain_name`; `account_id` unless default account configured | none | Retries validation for a Pages custom domain. |
| `verify_dns_route` | `hostname`, `target`; `zone_id` unless default zone configured | `proxied`, `ttl` | Validates route state vs desired intent. |
| `verify_http_gate` | `url` | `expected_state`, `timeout_ms` | `expected_state`: `access_gated` (default), `origin_reachable`, or `any`. |
| `upsert_dns_cname` | `hostname`, `target`; `account_id` and `zone_id` unless defaults configured | `proxied`, `ttl`, `override_publish_guard`, `override_reason`, `dry_run` | Publish-policy gated by default. |
| `list_access_apps` | `account_id` unless default account configured | `hostname` | Optional hostname filter. |
| `access_get_app` | `app_id`; `account_id` unless default account configured | none | Reads one Access application by ID. |
| `access_verify_hostname_gate` | `hostname`; `account_id` unless default account configured | none | Verifies whether a hostname is covered by a Cloudflare Access application. |
| `upsert_access_app` | `hostname`, `app_name`; `account_id` unless default account configured | `dry_run` | Idempotent create/update with validation readback. |
| `list_access_policies` | `app_id`; `account_id` unless default account configured | none | Reads policy list for an app. |
| `list_workers` | `account_id` unless default account configured | `tags` | Lists Worker scripts for the account. |
| `get_worker_settings` | `script_name`; `account_id` unless default account configured | `binding_name` | Reads Worker settings and optionally reports binding presence/readback. |
| `workers_list_scripts` | `account_id` unless default account configured | none | Lists Worker scripts using the newer Workers scripts endpoint. |
| `workers_get_script_settings` | `script_name`; `account_id` unless default account configured | none | Reads script settings from the Workers script settings endpoint. |
| `workers_upload_script` | `script_name`; `account_id` unless default account configured; exactly one of `script_path`, `script_content`, `script_content_base64`, or `multipart_path` | `main_module`, `metadata`, `content_type`, `dry_run`, `confirmation_token`, `reason` | Uploads a Worker module script or prebuilt multipart bundle through Cloudflare's Worker script endpoint. Dry-run prepares the upload and returns `required_confirmation_token` without calling Cloudflare; visible upload summaries include script/metadata SHA-256 digests and metadata keys, not raw metadata values. Apply requires that token, uploads the script or multipart bundle, then reads back Worker settings and returns `readback_verification`; module uploads fail closed with `workers.upload_readback_mismatch` when readback reports a different or missing `main_module`. The default elicitation configuration treats this as an action-time approval tool. |
| `workers_list_tails` | `script_name`; `account_id` unless default account configured | none | Lists configured Worker tail consumers for a script. |
| `patch_worker_settings` | `script_name`, `settings_patch`; `account_id` unless default account configured | `expect_binding`, `dry_run` | Patches Worker settings, reads back, and can verify a named binding/value. If Cloudflare reports that a Pages-generated Worker has no versions/versioned settings, the MCP returns `workers.pages_generated_worker_settings_immutable` and points the operator to update Pages project settings followed by a fresh `pages_deploy_directory` deployment. |
| `bindings_discover` | `account_id` unless default account configured | `include_workers`, `include_pages`, `name_contains` | Discovers Workers, Pages projects, and binding/resource references for wiring audits. |
| `workers_observability_query_events` | `account_id` unless default account configured | `script_name`, `datasets`, `filters`, `limit`, `timeframe`, `lookback_minutes`, `query_id`, `dry`, `view`, `needle` | Queries Workers Observability events using Cloudflare's documented `queryId`, `timeframe`, `dry`, top-level `limit`, and `parameters` body shape. `script_name` is optional and becomes a `$workers.scriptName` filter when provided; `datasets` defaults to `["workers"]`, `dry` defaults to `true`, and `view` defaults to `events`. |
| `workers_observability_list_keys` | `account_id` unless default account configured | `script_name`, `datasets`, `filters`, `limit`, `timeframe`, `lookback_minutes`, `needle`, `keyNeedle` | Lists Workers Observability telemetry keys with Cloudflare's documented top-level `from`/`to` time bounds rather than a nested `timeframe` object. `script_name` and `filters` are additive filters; `datasets` defaults to `["workers"]`. |
| `workers_observability_list_values` | `key`; `account_id` unless default account configured | `script_name`, `datasets`, `filters`, `limit`, `type`, `timeframe`, `lookback_minutes`, `needle` | Lists values for a telemetry key using `datasets`, `key`, `type`, and nested `timeframe`. `type` defaults to `string`, `datasets` defaults to `["workers"]`, and `script_name` is an optional additive filter. |
| `queues_list` | `account_id` unless default account configured | none | Lists Cloudflare Queues. |
| `queues_get` | `queue_id`; `account_id` unless default account configured | none | Reads Queue metadata and settings. |
| `queues_get_metrics` | `queue_id`; `account_id` unless default account configured | none | Reads realtime REST backlog metrics: `backlog_bytes`, `backlog_count`, and `oldest_message_timestamp_ms`; also reports computed `oldest_message_age_ms` when possible. |
| `queues_list_consumers` | `queue_id`; `account_id` unless default account configured | none | Lists Queue consumers, including Worker/HTTP pull consumer settings, retry limits, and configured dead-letter queues when returned by Cloudflare. |
| `queues_health` | `queue_id`; `account_id` unless default account configured | `include_dlq` | Combines Queue settings, backlog metrics, consumer status, purge status, and configured DLQ backlog. Historical retry/failure counts are explicitly reported as not available in this REST health tool because Cloudflare exposes that history through Queues GraphQL analytics. |
| `cache_purge` | one purge mode in `payload`; `zone_id` unless default zone configured | `environment_id`, `confirmation_token`, `dry_run` | Purges by everything, files, tags, hosts, or prefixes; purge-everything apply requires dry-run token. |
| `cache_zone_setting` | `action`, `setting_id`; `zone_id` unless default zone configured | `value`, `dry_run` | Reads or updates cache-related zone settings. |
| `cache_rules` | `action`; `zone_id` unless default zone configured | `phase`, `rule_id`, `rule`, `rules`, `confirmation_token`, `dry_run` | Manages Cache Rules and Cache Response Rules through Rulesets phases. |
| `cache_reserve` | `action`; `zone_id` unless default zone configured | `resource`, `payload`, `dry_run` | Reads/updates Cache Reserve and reserve-clear status. |
| `cache_tiered` | `action`; `zone_id` unless default zone configured | `resource`, `payload`, `dry_run` | Reads/updates/deletes Smart or Regional Tiered Cache. |
| `cache_variants` | `action`; `zone_id` unless default zone configured | `resource`, `payload`, `dry_run` | Reads/updates/deletes cache variants settings. |
| `cache_origin_regions` | `action`; `zone_id` unless default zone configured | `resource`, `payload`, `dry_run` | Manages deprecated origin cloud-region cache mappings where exposed by Cloudflare. |
| `bulk_redirects_list_lists` | `account_id` unless default account configured | `include_non_redirect` | Lists account rules lists, filtered to Bulk Redirect lists unless `include_non_redirect=true`. |
| `bulk_redirects_get_list` | `list_id`; `account_id` unless default account configured | none | Reads one Bulk Redirect list. |
| `bulk_redirects_list_items` | `list_id`; `account_id` unless default account configured | `cursor`, `per_page` | Lists redirect items in a Bulk Redirect list. |
| `bulk_redirects_create_list` | `name`; `account_id` unless default account configured | `description`, `dry_run` | Creates a Bulk Redirect list through dry-run/apply planning. |
| `bulk_redirects_update_list` | `list_id`; `account_id` unless default account configured | `name`, `description`, `dry_run` | Updates Bulk Redirect list metadata through dry-run/apply planning. |
| `bulk_redirects_import_items` | `list_id`, `redirects[]`; `account_id` unless default account configured | `mode`, `dry_run` | Imports redirect items to a list; `mode` defaults to `append`. |
| `bulk_redirects_get_operation` | `operation_id`; `account_id` unless default account configured | none | Reads a Bulk Redirect import operation. |
| `bulk_redirects_get_ruleset` | `account_id` unless default account configured | none | Reads the account-level Bulk Redirect Ruleset. |
| `bulk_redirects_attach_list_to_ruleset` | `list_name`; `account_id` unless default account configured | `rule_description`, `enabled`, `dry_run` | Attaches a Bulk Redirect list to the account-level redirect Ruleset through dry-run/apply planning. |
| `email_routing_get_settings` | `zone_id` unless default zone configured | none | Reads Email Routing zone settings. |
| `email_routing_get_dns` | `zone_id` unless default zone configured | none | Reads Email Routing DNS record status for a zone. |
| `email_routing_list_rules` | `zone_id` unless default zone configured | `page`, `per_page` | Lists Email Routing rules. |
| `email_routing_get_rule` | `rule_identifier`; `zone_id` unless default zone configured | none | Reads one Email Routing rule. |
| `email_routing_get_catch_all` | `zone_id` unless default zone configured | none | Reads the Email Routing catch-all rule. |
| `email_routing_list_addresses` | `account_id` unless default account configured | `page`, `per_page` | Lists destination addresses for Email Routing. |
| `email_routing_get_address` | `destination_address_identifier`; `account_id` unless default account configured | none | Reads one Email Routing destination address. |
| `replace_access_policies` | `app_id`, `policies[]`; `account_id` unless default account configured | `dry_run` | Low-level policy replacement. Existing policies with supplied `id` values are updated through Cloudflare's per-policy endpoint; omitted policies are deleted; policies without `id` are created. |
| `apply_access_allowlist` | `app_id`, `requested_principals[]`; `account_id` unless default account configured | `mode`, `dry_run` | `mode` is `replace` (default) or `additive`; enforces post-apply invariants. |
| `publish_preflight` | `hostname`; `account_id` unless default account configured | `override_publish_guard`, `override_reason` | Read-only policy gate decision. |
| `lock_first_publish` | `hostname`, `target`; `account_id` and `zone_id` unless defaults configured | `proxied`, `ttl`, `override_publish_guard`, `override_reason`, `dry_run` | Policy gate evaluation occurs before DNS mutation. |
| `emergency_unpublish` | `hostname`; `zone_id` unless default zone configured | `reason`, `dry_run` | Idempotent emergency route disable. |
| `portal_agent_request` | `url` | `method`, `body`, `use_agent_token`, `use_access_service_token`, `dry_run` | Allowlisted bridge to operator endpoints. Dry-run reports request/auth metadata without sending the request; live calls attach configured server-held credentials only when requested. |

## Structured payload details for complex tools

`replace_access_policies` expects each `policies[]` item as:

```json
{
  "id": "optional-existing-policy-id",
  "name": "mcp-managed-allowlist-email",
  "decision": "allow",
  "include": { "email": { "email": ["user@example.com"] } },
  "exclude": null,
  "require": null,
  "precedence": 1
}
```

`generate_tunnel_ingress` accepts `rules[]` items as objects:

```json
{
  "hostname": "preview.example.com",
  "service": "http://127.0.0.1:3000"
}
```

`hostname` may be omitted only for the final catch-all rule:

```json
{ "service": "http_status:404" }
```

String shorthand is also accepted. Hostname rules must use `->` or `=>`;
service-only shorthand is accepted only for `http_status:*` catch-all rules:

```json
[
  "preview.example.com -> http://127.0.0.1:3000",
  "http_status:404"
]
```

Rules are emitted in caller-provided order because cloudflared ingress order is
semantic. The catch-all rule must be last. If no catch-all rule is provided,
the planner appends `service: http_status:404`.

`patch_worker_settings` expects `settings_patch` to be a JSON object
accepted by Cloudflare's Worker script settings endpoint. For binding
verification, pass `expect_binding`:

```json
{
  "name": "DESTINATION",
  "binding_type": "plain_text",
  "field": "text",
  "value": "https://example.com"
}
```

`workers_upload_script` is the curated MCP path when an agent needs to deploy a
Worker script body instead of only checking settings/readback. For a simple
module upload, pass `script_path` or `script_content` plus `main_module` and any
Cloudflare metadata such as `compatibility_date` in `metadata`. For projects
that already use Wrangler to produce a multipart Worker bundle, pass
`multipart_path`; the MCP infers the multipart boundary when the file starts
with `--<boundary>`. Apply requires the dry-run token and returns both the
Cloudflare upload response and `readback_settings`. The visible upload summary
reports script and metadata SHA-256 digests plus metadata keys rather than raw
metadata values, and module uploads fail closed if settings readback reports a
different `main_module` than the requested upload. Multipart bundle uploads
report module-name readback verification as not applicable because the bundle
owns its module graph.

## Mutating call requirements

For all mutating tools (`api_mutate`, `account_api_tokens`, `r2_put_object`, `ensure_tunnel`, `connector_control`, `upsert_dns_cname`, `upsert_access_app`, `replace_access_policies`, `apply_access_allowlist`, `patch_worker_settings`, `workers_upload_script`, `cache_purge`, `cache_zone_setting`, `cache_rules`, `cache_reserve`, `cache_tiered`, `cache_variants`, `cache_origin_regions`, `lock_first_publish`, `emergency_unpublish`, `portal_agent_request`):

- Run once with `dry_run=true` before apply.
- Send `x-correlation-id` for audit traceability.
- Expect `plan` and `audit` in response payloads.
- In read-only mode (`CLOUDFLARE_MCP_READ_ONLY=1`), mutating tools are not callable (`method_not_found`).
- In curated-tools-only mode (`CLOUDFLARE_MCP_API_PARITY_ENABLED=0`), generic API parity tools (`api_parity_status`, `api_find_operations`, `api_get_operation`, `api_prepare_call`, `api_read`, `api_mutate`) are hidden and not callable.
- If elicitation is enabled and the tool is configured as dangerous, expect approval prompts before apply execution.
- Broad cache actions add local confirmation: `cache_purge` with `payload.everything=true` and `cache_rules` with `action=replace_all` require echoing the token returned by dry-run. `workers_upload_script` also requires echoing the dry-run token for apply because it deploys executable Worker code.
- For `api_mutate`, clients should send `body` as a JSON object/array/value, not
  an escaped JSON string. The server normalizes valid JSON strings for
  compatibility, but dry-run output must be reviewed: if
  `body_normalized_from_json_string=false` and the body is still a string, do
  not apply to endpoints that require object bodies.

## External service bridge request contract

`portal_agent_request` sends an HTTP request to an approved external service
endpoint. The server attaches configured credentials internally:

- `use_agent_token=true` attaches `CLOUDFLARE_MCP_PORTAL_AGENT_TOKEN` or
  the configured token-file fallback as a bearer token.
- `use_access_service_token=true` attaches
  `CLOUDFLARE_MCP_ACCESS_CLIENT_ID` and
  `CLOUDFLARE_MCP_ACCESS_CLIENT_SECRET` as Cloudflare Access service-token
  headers. These values may also come from
  `CLOUDFLARE_MCP_ACCESS_CLIENT_ID_FILE` and
  `CLOUDFLARE_MCP_ACCESS_CLIENT_SECRET_FILE`.
- Live credential failures include non-secret auth diagnostics, including
  whether the running MCP process has each requested credential configured.
- Secret files must be regular files. On Unix, they must be owner-only
  readable/writable, such as mode `0600`; group/world-readable files fail
  closed at startup.
- `url` must be HTTPS and start with one configured
  `CLOUDFLARE_MCP_PORTAL_ALLOWED_URL_PREFIXES` entry.
- `method` defaults to `POST`; supported values are `GET`, `POST`, `PUT`,
  `PATCH`, and `DELETE`.
- `body` is optional JSON. Dry-run responses report only body kind, not body
  contents.
- Outputs include status and sanitized response data, never configured secret
  values.

Dry-run portal request:

```json
{
  "name": "portal_agent_request",
  "arguments": {
    "url": "https://ops.example.com/api/agent/task",
    "method": "POST",
    "body": {
      "title": "Operator note",
      "content": "..."
    },
    "use_agent_token": true,
    "use_access_service_token": true,
    "dry_run": true
  }
}
```

## Example request sequence

Initialize:

```bash
curl -i -X POST http://127.0.0.1:9501/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"initialize",
    "params":{
      "protocolVersion":"2024-11-05",
      "capabilities":{},
      "clientInfo":{"name":"example-client","version":"0.1.0"}
    }
  }'
```

Dry-run mutating call:

```bash
curl -i -X POST http://127.0.0.1:9501/mcp \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Session-Id: <session-id>' \
  -H 'x-correlation-id: deploy-preview-2026-02-22T12:00:00Z' \
  -H 'x-request-id: req-123' \
  -d '{
    "jsonrpc":"2.0",
    "id":2,
    "method":"tools/call",
    "params":{
      "name":"lock_first_publish",
      "arguments":{
        "account_id":"<acct>",
        "zone_id":"<zone>",
        "hostname":"preview.example.com",
        "target":"<tunnel-id>.cfargotunnel.com",
        "proxied":true,
        "ttl":1,
        "dry_run":true
      }
    }
  }'
```

## Client readiness checklist

1. Configure host allowlist and bind settings (`CLOUDFLARE_MCP_ALLOWED_HOSTS`, bind addr).
2. Configure auth mode and token flow expected by your client.
3. Configure Cloudflare API token and optional default account/zone IDs.
4. Initialize session and verify `health` succeeds.
5. Run mutating operations with `dry_run=true` and correlation headers.
6. Apply only after policy gate decisions and dry-run plans are approved.
