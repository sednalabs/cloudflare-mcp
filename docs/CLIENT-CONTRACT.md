# Cloudflare MCP Client Contract

This document is the client-facing request contract for `cloudflare-mcp`: what to send, what is required, and what safety headers to include.

Related docs:
- `../README.md` for setup/auth/systemd/Codex wiring.
- `./RUNBOOK.md` for phased rollout and rollback sequencing.

## Protocol and endpoint requirements

- Transport: MCP Streamable HTTP.
- MCP endpoint: `POST|GET|DELETE /mcp`.
- `/mcp/` is accepted and normalized to `/mcp`.
- Public endpoints (no MCP bearer auth by policy): `GET /health`, `GET /attest`,
  and `GET /oauth/cloudflare/callback`. All remain subject to the Host allowlist.

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
- Cloudflare upstream API credentials are independent from MCP bearer auth.
  Static credentials use `CLOUDFLARE_MCP_API_TOKEN_SOURCE` values `config`,
  `header`, or `header_or_config`. Hosted authorization can instead use the
  `CLOUDFLARE_MCP_UPSTREAM_OAUTH_*` settings and the
  `cloudflare_auth_status`, `cloudflare_auth_login`,
  `cloudflare_auth_probe`, and `cloudflare_auth_logout` tools.
- Credential precedence is request header, configured static token, then the
  hosted OAuth grant. Setup tools remain callable before a provider grant is
  present.
- The OAuth callback consumes a bounded, expiring, single-use PKCE transaction.
  Clients must never log or copy its `code` or `state` query values.
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

For `d1_bootstrap_migration_ledger` and `d1_apply_migration_manifest`, a live `approved_plan_sha256` is the exact lowercase 64-character `plan_sha256` returned by that tool's dry run. Case changes and surrounding whitespace are rejected so apply and retained recovery bind one canonical approval identity. The bootstrap plan is valid only for the same exact account, database, ledger-table identity, canonical initializer bytes, and primary-served empty schema observed by the live preflight. Manifest names may be current Wrangler relative POSIX paths such as `0001_init/migration.sql`, not only flat basenames. They must be canonical and are ordered with Wrangler's segment-wise leading-number comparison and lexical tie-breaking; absolute paths, backslashes, empty segments, `.`/`..`, and NUL are rejected.

Every curated provider mutation for an existing D1 database requires the exact
account identifier and a canonical lowercase hyphenated UUID `database_id`.
Uppercase, mixed-case, compact, braced and other database UUID aliases fail
before target hashing, planning, custody lookup or provider dispatch; callers
must not normalize a rejected identifier themselves.

The canonical target-identity contract has a one-way local custody activation
boundary. Before either a migration lease or another existing-target mutation
guard can be created, the configured lease root must contain the exact
`target-identity-v2.activation.json` marker and one exact create-only
`target-identity-v2.<target-key-sha256>.receipt.json` registration for the
canonical target. An upgraded process may create the first registration and
marker only while holding the permanent root activation guard and only after a
bounded, descriptor-relative enumeration proves the root was empty before the
guard was created. Any unversioned target directory or other entry blocks,
including an otherwise canonical incumbent and active, retiring, retired,
terminal, malformed, unreadable, or alias custody. The MCP never deletes,
migrates, or blesses that evidence. This is necessary because predecessor
lease payloads retain the derived target hash but cannot prove which UUID
spelling produced it. Upgrade by stopping every predecessor writer, preserving
and governing its old root separately, and configuring all upgraded writers to
one newly provisioned private empty root. Never point a predecessor binary at
an activated root. That complete predecessor drain is a separate deployment
prerequisite; it does not replace runtime enforcement. Marker-present calls
perform a stable bounded audit of the marker, every registration, and every
registered target's complete allowed custody namespace. The same audit is
revalidated at guard, lease, provider, persistence, and release boundaries, so
an alias, malformed entry, unknown entry, contradictory lease state, or target
without registration fails closed even if it appears after activation.
Rollback is generation-wide: stop every upgraded writer, preserve the
activated root without manual edits, and return all writers together to the
preserved predecessor root and predecessor binary generation. Mixed roots or
binary generations are unsupported during cutover or rollback.

The exact family `migration-ledger-bootstrap-v1` is reserved to `d1_bootstrap_migration_ledger` and its dedicated reconcile, finalize, and abort tools. Generic manifest apply, read-only reconciliation, and terminal finalization reject that family before provider access, custody inspection or creation, receipt access, or local namespace mutation; similarly prefixed family labels are not reserved.

Cloudflare D1 already enforces foreign keys and runs each query or migration in
an implicit transaction, so a migration cannot enable enforcement with
`PRAGMA foreign_keys = ON`. The manifest tool preserves that exact reviewed
source text, size, and SHA-256, but execution transform
`drop-leading-pragma-foreign-keys-on-v1` removes the pragma only when it is the
byte-exact first statement `PRAGMA foreign_keys = ON;` followed by two LF
bytes and non-empty migration SQL. Dry-run and apply responses expose the
transform ID/version, executed byte count and SHA-256, and complete provider
statement SHA-256. A transformed version-2 plan binds those fields; its digest
then binds lease custody, retained reconciliation, terminal receipt,
finalization, and exact replay. Case, whitespace, comment, duplicate, embedded,
empty-remainder, or otherwise ambiguous `foreign_keys` forms cannot produce a
new plan and fail before provider or local custody mutation. Read-only retained
reconciliation continues to recognize an exact predecessor version-1 plan so
its existing assertion grammars and terminal recovery remain compatible; that
compatibility never authorizes a fresh apply. Manifests without this exact
prefix retain the existing version-1 plan digest.

| Tool | Required arguments | Optional arguments | Notes |
| --- | --- | --- | --- |
| `health` | none | none | Runtime status summary. |
| `find_tools` | none | `query`, `group`, `read_only`, `limit`, `include_schema` | Searches local tool metadata for non-hosted deferred-loading clients and returns `openai_allowed_tools`; with `include_schema=true`, returns MCP tool objects keyed by tool name. Hosted OpenAI `tool_search` does not call this tool automatically. |
| `api_parity_status` | none | none | Summarizes the committed Cloudflare REST API v4 catalog and generic executor coverage. |
| `api_find_operations` | none | `query`, `tag`, `method`, `scope`, `risk`, `include_deprecated`, `limit` | Searches the official OpenAPI-derived operation catalog. |
| `api_get_operation` | `operation_id` | none | Shows parameters, risk, call template, executor, and preferred curated tool when one exists. |
| `api_prepare_call` | `operation_id` or enough search filters | `query`, `tag`, `method`, `scope`, `risk`, `include_deprecated`, `path_params`, `query_params`, `body`, `limit` | Resolves an operation and returns exact `api_read`/`api_mutate` arguments. Ambiguous searches return candidates instead of guessing; mutating operations are prepared as `dry_run=true`. Path parameters are derived from the URL template as well as catalog metadata, so stale catalog `path_params` cannot leave literal `{account_id}` placeholders in prepared paths. The returned `resolved_path_params` and `call.arguments.path_params` include configured account/zone defaults, making the prepared call self-contained. |
| `api_read` | `operation_id` | `path_params`, `query`, `max_bytes` | Executes catalog `GET` operations only; uses configured account/zone defaults for matching path params. Path parameters are derived from the URL template as well as catalog metadata. |
| `api_mutate` | `operation_id` | `path_params`, `query`, `body`, `dry_run`, `confirmation_token`, `reason`, `token_permissions` | Executes catalog `POST`/`PUT`/`PATCH`/`DELETE` operations through dry-run confirmation; high-risk and denied-by-default operations fail closed before request construction or provider access. `token_permissions` carries permission-group names from a fresh `account_api_tokens action=get` readback for operations with an explicit multi-permission preflight. The Bot Management zone update requires both `Bot Management Write` and `Zone Settings Write`; its dry-run withholds the confirmation token until both are reported, and returns guarded MCP token-repair calls when either is unverified or missing. The generic `worker-script-put-content` upload is denied; use `workers_upload_script` for its digest-bound upload, confirmation, and readback contract. Every generic non-GET D1 operation whose path contains an existing `database_id` is denied: delete, export, import, query/raw query, time-travel restore, full update and partial update. Use curated D1 read, rename, delete, row-write, bootstrap, and migration-manifest tools only where their narrower contract applies; the rename-only tool is not a preferred substitute for the broader partial-update operation. Surfaces without a complete guarded curated lifecycle remain unavailable through `api_mutate`. D1 create is not an existing-target operation, and GET operations retain their read policy. Valid escaped JSON-string `body` values are normalized into real JSON and reported with `body_normalized_from_json_string`. |
| `account_billing_usage` | none if default account configured | `account_id`, `mode`, `from`, `to`, `metric`, `max_bytes` | Read-only account usage helper for billing investigations. `mode=paygo` calls `/accounts/{account_id}/paygo-usage`; `mode=billable_usage` calls `/accounts/{account_id}/billable/usage` and requires `metric`. Use this for billable usage records before using analytics to explain attribution. |
| `graphql_analytics_query` | `query` | `variables`, `max_bytes` | Runs a read-only Cloudflare Analytics GraphQL query against `/client/v4/graphql`. Mutations and subscriptions are rejected before HTTP. Use this for product analytics such as D1 `d1AnalyticsAdaptiveGroups` and `d1QueriesAdaptiveGroups`; Cloudflare documents GraphQL analytics as attribution/analytics data, not a billing-record replacement. When the MCP can distinguish likely authz cause classes, responses include `diagnostics.authz_classification` with a stable `code` and next-step guidance. |
| `waf_ruleset_summary` | none if default zone or account configured | `account_id`, `zone_id`, `scope`, `phases`, `include_rules`, `include_raw`, `max_bytes` | Reads WAF Ruleset Engine entrypoints for custom rules, managed rules, and rate limiting rules. `scope=auto` prefers zone scope, then account scope. `phases` accepts aliases such as `custom`, `managed`, and `ratelimit`; defaults to `http_request_firewall_custom`, `http_request_firewall_managed`, and `http_ratelimit`. |
| `waf_security_events_summary` | `zone_id` unless default zone configured | `window_hours`, `since`, `until`, `group_by`, `action`, `source`, `host`, `path`, `client_ip`, `rule_id`, `limit`, `sample_limit`, `include_query`, `max_bytes` | Runs a curated read-only Cloudflare Analytics GraphQL query over the Security Events dataset `firewallEventsAdaptive`. Defaults to a 24-hour window, grouped by action/source/host/path/country/hour, with recent samples. Grouped authz degradations may include `diagnostics.authz_classification` so downstream helpers can distinguish wrong context from grouped-path-only access blocks. |
| `waf_rule_activity` | `rule_id`; `zone_id` unless default zone configured for analytics | `account_id`, `zone_id`, `scope`, `phases`, `window_hours`, `since`, `until`, `sample_limit`, `include_query`, `include_raw`, `max_bytes` | Finds a WAF rule in current Rulesets and queries recent Security Events for the same rule ID. For account-scoped ruleset lookup, still provide `zone_id` for the zone-scoped `firewallEventsAdaptive` dataset. Grouped authz degradations may include `diagnostics.authz_classification` with stable cause codes. |
| `waf_ruleset_plan_change` | `edits[]`; `zone_id` or `account_id` unless defaults configured | `scope`, `phase`, `max_rules`, `stale_list_refs`, `empty_list_refs`, `fail_on_stale_lists`, `reason`, `max_bytes` | Reads one WAF Ruleset Engine entrypoint, applies typed in-memory edits, and returns `planned_ruleset`, stable `diff`, rule-cap/list validation, before/after ordering, contextual performance readback notes, and `required_confirmation_token`. No Cloudflare mutation is applied. `phase` defaults to `custom`; use aliases such as `custom`, `managed`, or `ratelimit`. |
| `waf_ruleset_apply_change` | same edit target and `confirmation_token`; `zone_id` or `account_id` unless defaults configured | `scope`, `phase`, `max_rules`, `stale_list_refs`, `empty_list_refs`, `fail_on_stale_lists`, `reason`, `readback_security_events`, `readback_window_hours`, `readback_sample_limit`, `max_bytes` | Recomputes the plan, requires the exact token from `waf_ruleset_plan_change`, updates the Ruleset entrypoint, reads back the Ruleset, and optionally queries recent Security Events for changed rule IDs/refs. Responses include mutation audit metadata and the deterministic mutation plan. |
| `account_api_tokens` | `action`; `account_id` unless default account configured | `token_id`, `query`, `body`, `dry_run`, `confirmation_token`, `reason`, `max_bytes` | Curated account API token management. Read actions do not prompt under elicitation; mutating actions use dry-run confirmation and audit metadata. |
| `account_api_token_permission_plan` | `token_id` or `current_token`; `account_id` unless default account configured | `policy_index`, `add_permissions`, `remove_permissions`, `permission_groups`, `include_catalog`, `reason`, `max_bytes`; aliases `add`, `add_scopes`, `remove`, `remove_scopes` | Read-only permission delta planner for existing account API tokens. Fetches or accepts current token details and permission groups, resolves permission group ids/names/exact scopes, preserves existing policy permissions unless explicitly removed, and returns the exact `account_api_tokens action=update dry_run=true` payload. For multi-policy tokens, requires explicit `policy_index`. |
| `capabilities_check` | `account_id` and `zone_id` unless defaults configured | `expected_account_id`, `expected_zone_id`, `expected_zone_name`, `require_explicit_zone_id` | Operator preflight for the MCP call boundary, effective target identity, and representative account/zone API probes. The response is produced inside a normal MCP `tools/call` handler, so `preflight.mcp.tool_call_reached_handler=true` proves the client initialized and reached the same MCP boundary used by ordinary tools. Pass expected account/zone values for deployment work; mismatches and default-zone drift are reported under `preflight.findings` and set `preflight.ok=false`. |
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
| `d1_execute_write` | `database_id`, `sql`; `account_id` unless default account configured | `params`, `dry_run`, `max_rows` | Executes one audited D1 row-write statement after dry-run planning. Allows only single-statement `INSERT`, `UPDATE`, `DELETE`, or `REPLACE`; schema-changing migration SQL belongs in `d1_apply_migration_manifest`. |
| `d1_apply_migrations` | `database_id`, `migrations_directory`; `account_id` unless default account configured | `migrations_table`, `dry_run`, `max_rows` | Legacy directory-backed migration surface. `dry_run=true` performs remote ledger readback without writes and returns `already_applied`, `skipped_migrations`, `pending_migrations`, and `unknown_ledger`. Live mutation is retired and returns `d1.legacy_migration_apply_retired` with zero provider calls; use `d1_apply_migration_manifest` for every provider migration write. |
| `d1_bootstrap_migration_ledger` | `database_id`; `account_id` unless default account configured | `migrations_table`, `dry_run`, `approved_plan_sha256` | Narrow first-ledger bootstrap for an independently selected empty D1 target. Dry run requires two identical, bounded, primary-served `sqlite_master` reads proving that no application-owned object exists; SQLite internals and Cloudflare's reserved `_cf_*` family are excluded by object and parent identity, and custom ledger names in either reserved family are rejected before provider access. Every bootstrap inventory or ledger read uses the bounded recovery HTTP boundary: exactly one attempt, no redirects, a 16 MiB response cap, strict envelope decoding, exact complete-body digest/size when available, and explicit dispatch/response/body/status lifecycle evidence. Every chronological lifecycle/response entry retains its bounded `dry_run_preflight`, `live_predispatch`, `ambiguous_write_reconciliation`, or `post_write_proof` window plus `inventory.first`/`inventory.second`/`ledger.first`/`ledger.second` read identity and query digest even when no response bytes exist. `provider_calls` therefore counts physical attempted requests; token/config/request-builder rejection is pre-dispatch and counts zero. HTTP errors, transport loss, truncated/oversized/malformed/invalid-UTF-8 bodies, non-boolean or absent primary markers, and unstable paired results fail closed without adapter retry. Nested provider causes, including the one non-idempotent initializer failure, contain safe code/status plus `retryable=false` and `operator_guidance=reconciliation_only`. A completely read, duplicate-free authenticated initializer HTTP error may additionally expose only the allowlisted provider code/category pair and a bounded numeric SQL byte offset when the provider message ends in the recognized form. Generic messages, hints, arbitrary adapter classifications, SQL, and provider-body excerpts remain omitted; complete-body digest and size remain evidence. It emits a digest bound to the exact target, table, empty state, and canonical Wrangler-compatible initializer. Live apply uses the same account/database target lease as manifest apply, repeats the stable empty proof under custody, and dispatches exactly one non-idempotent ledger-table initializer. It never executes migration SQL and never converts an existing or partially initialized database. The DDL acknowledgement must be one clean primary-served result with `changed_db=true` and typed non-negative counts; zero row counts are valid for this DDL-only call, while the stable canonical-schema and empty-ledger post-readback proves the effect. A lost or ambiguous write response triggers only the same exact bounded read boundary, retains custody when provable, reports one provider mutation plus chronological ambiguity evidence, and never authorizes automatic retry. |
| `d1_reconcile_bootstrap_migration_ledger` | `database_id`, `approved_bootstrap_plan_sha256`, `lease_nonce`, `lease_payload_sha256`; `account_id` unless default account configured | `migrations_table` | Bootstrap-only read-only recovery for exact retained `migration-ledger-bootstrap-v1` custody. It rederives the plan from the exact target, table and canonical initializer, validates the exact lease family/nonce/payload, and performs two stable primary proof windows. Each window contains two bounded schema inventory reads and two empty-ledger reads. Every read is exactly one HTTP attempt through the no-redirect recovery client; exact response-byte digest/size and dispatch/response/body/status lifecycle are retained, while `provider_calls` counts only actual dispatches and pre-dispatch failures count zero. Only the exact installed initializer schema as the sole application-owned object with zero ledger rows in both matching windows returns `terminal_proof_ready`. It reports eight provider calls, zero provider/local mutations, exact initializer/query/snapshot/reconciliation digests, unknown effect attribution, retained custody, and a permanent no-retry decision. Ledger absence, extra/drifted schema, or a non-empty ledger is explicit conflict; malformed, non-primary, unreadable, unstable, or custody-drifted evidence is unknown. No manifest input or caller SQL is accepted. |
| `d1_finalize_bootstrap_migration_ledger` | All exact bootstrap reconciliation inputs; `expected_reconciliation_plan_sha256`, `expected_initializer_authority_sha256`, `expected_query_authority_sha256`, `expected_canonical_snapshot_sha256`, and distinct `terminal_request_sha256`/`terminal_attempt_sha256` | `migrations_table`, `dry_run`, `approved_terminal_plan_sha256` (required live) | Separately approval-gated local-custody finalizer that never issues provider writes. Dry run reproduces the exact eight-read bootstrap proof and returns a terminal-plan digest. Live execution requires that digest, repeats the proof, makes a fresh four-read stable primary proof before create-only canonical receipt persistence, repeats another four-read proof before guarded active -> retiring -> retired custody transitions, and then re-reads the exact receipt/retirement products. Every provider read retains the same one-attempt lifecycle and exact response-byte evidence as read-only reconciliation. Any changed authority, provider conflict/unknown state, custody drift, or receipt conflict is nonterminal and keeps retry forbidden. Custody drift never emits a stale retain decision: it reports `lease_retained=null` and unverified custody; if the drift follows receipt persistence, it truthfully reports the known creation mutation while blocking retirement. The final descriptor-bound readback is authoritative for current receipt state: failure reports its exact `true`, `false`, or `null` evidence rather than substituting the earlier creation fact. Exact completed replay verifies the receipt and retirement with zero provider calls. The general manifest recovery tools cannot substitute an empty manifest for this bootstrap family. |
| `d1_abort_bootstrap_migration_ledger` | `database_id`, `approved_bootstrap_plan_sha256`, `lease_nonce`, `lease_payload_sha256`, and distinct `terminal_request_sha256`/`terminal_attempt_sha256`; `account_id` unless default account configured | `migrations_table`, `dry_run`, `approved_terminal_plan_sha256` (required live) | Provider-free terminal abort for exact bootstrap custody created under the marker-before-dispatch protocol. Every such live bootstrap durably records an exact initializer-attempt receipt before provider dispatch. The abort tool accepts only a stable absence proof for that marker under the held target guard; legacy custody, any attempted/ambiguous initializer, malformed or contradictory marker evidence, conflicting/absent lease evidence, or retirement without the exact receipt fails closed with zero provider calls. Dry run emits an approval-bound terminal plan. Live execution creates a canonical `not_committed` receipt, repeats the zero-dispatch proof, then retires active -> retiring -> retired custody. Exact completed replay converges with zero provider and local mutations; changed terminal identity conflicts. Successful retirement permits only a fresh bootstrap dry run, never replay of the incumbent attempt. |
| `d1_apply_migration_manifest` | `database_id`, `migration_family`, complete exact-byte `manifest[]`; `account_id` unless default account configured | `migrations_table`, `dry_run`, `approved_plan_sha256`, `max_rows` | Guarded successor for high-custody migrations. The manifest carries each basename, exact UTF-8 SQL bytes, byte length, and SHA-256; no migration directory is reopened after review. The aggregate exact SQL payload is capped at 16 MiB and is moved, not cloned, into validation; Streamable HTTP ingress is independently bounded before parsing. Dry run performs one primary-served existing-Wrangler-ledger read, requires it to be an exact manifest prefix, and returns a digest that binds account, database, table, family, manifest, and ledger. Every ledger result set used by plan, apply, readback, or ambiguity reconciliation must explicitly contain literal boolean `meta.served_by_primary=true`; missing, false, non-boolean, malformed, duplicate, or unstable evidence fails closed. Every migration-write result set must additionally have boolean `meta.changed_db` and JSON-integer `meta.changes` and `meta.rows_written`. A non-mutating successful result must report `changed_db=false` with both counts zero; the complete response must prove at least one `changed_db=true` result plus positive aggregate changes and rows-written totals. Missing, malformed, failed, zero-total, or contradictory write evidence is `reconciliation_required` and never authorizes a retry. Canonical account/database identities are used for every provider call, plan, and lease key; raw surrounding whitespace aliases and dot path segments are rejected, and the shared adapter percent-encodes account/database URL segments. A live call first performs a read-only inspection of existing target custody, so retained active or retiring evidence blocks before any provider request and an absent target creates no local state. Before a new lease or migration SQL, two independent reads must agree that `sqlite_master` contains exactly the configured canonical ledger table, with the required exact schema, no ledger trigger, and `meta.served_by_primary=true`; the closed accepted schema set includes this MCP's initializer plus the exact quoted current-Wrangler and unquoted legacy-Wrangler spellings, without general SQL normalization. Absent, malformed, case-conflicting, wrong-type, wrong-target, wrong-schema, non-primary, or unstable authority evidence fails closed without a new local or provider mutation. After lease and plan binding, that stable proof is repeated immediately before every migration mutation and again before successful custody release; any failure after a write retains reconciliation custody and stops later writes. Each proof is followed by held-custody revalidation immediately before dispatch or release. Live apply requires Linux and one permanent account/database target directory below `CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT`; it independently uses stable pre- and post-apply ledger readback. Held root, target, guard and active descriptors are identity-checked, and every active, abort and retirement transition is target-dirfd-relative. The directory has a permanent `guard.lock` and durable `active.lease.json`; the key is account/database, not family. Root, ancestors, target, guard and active evidence are revalidated as private, non-symlink current-operator files while the guard is held. A present, malformed, symlink or non-regular active or retiring entry is never reclaimed automatically and stops another apply before any provider request. Normal completion first records `retiring.lease.json`, then `retired.<nonce>.lease.json`, with a synchronization at each boundary; failed synchronization restores exact active evidence or leaves an explicit active/retiring blocker. Failed creation is preserved as `aborted-create.<nonce>.lease.json`, but only after verifying the active namespace entry is still the held owner's file. No production cleanup unlinks lease evidence. Each migration is submitted as one non-idempotent D1 provider write and may return one or more successful query-result entries; every returned entry must be structurally valid and successful before application is claimed. Provider response ambiguity stops immediately with reconciliation evidence and no retry. A completely read, duplicate-free authenticated HTTP error may expose only the allowlisted provider code/category pair and a bounded numeric SQL byte offset when the provider message ends in a recognized offset form; arbitrary message text and SQL remain discarded while the complete-body digest and size remain evidence. The tool revalidates local custody after that ambiguity before reporting retained custody; if it cannot prove that chain, it reports `lease_retained=null` and `custody_status=lost_or_unverifiable_after_ambiguous_apply`, retains only prior identity as historical context, and explicitly forbids replay even if local evidence is absent. Reconciliation results distinguish known contradictory ledger evidence from unknown/unreadable state and retain both supplied and computed plan digests where applicable. The lease guarantee is limited to a trusted Linux filesystem that supports working `renameat2(RENAME_NOREPLACE)`, directory `fsync`, and advisory locks; cross-host or shared-filesystem semantics require separate proof. Retained evidence requires the product-neutral governed recovery path before another apply. Non-Linux builds or unsupported filesystems fail closed before provider I/O. |
| `d1_reconcile_migration_manifest` | `database_id`, `migration_family`, complete exact-byte `manifest[]`, `approved_plan_sha256`, `lease_nonce`, `lease_payload_sha256`, ordered bounded `state_expectations[]` covering every prefix from zero through the full manifest; `account_id` unless default account configured | `migrations_table`, `effect_assertion_id` | Read-only recovery boundary for exactly one retained `active.lease.json` or `retiring.lease.json`. It locks the existing permanent guard, binds exact canonical target/family/plan/nonce/payload identity, and never creates, renames, rewrites, retires, or unlinks custody evidence. The caller cannot supply SQL. The tool derives the complete CREATE object inventory for every prefix and rejects caller omissions/additions. It first runs one bounded primary-current ledger-selection query, then constructs one bounded complete SELECT batch whose `sqlite_master` catalog covers the full derived manifest object-name union while `table_xinfo`, `foreign_key_list`, bounded `foreign_key_check`, and seed statements cover only the exact selected-prefix tables. A future table absent at the selected prefix is never probed, while its premature catalog presence remains detectable. Every result set has a query-bound identity sentinel and must carry exact `meta.served_by_primary=true` evidence; absent, false, null, non-boolean, or mixed primary markers fail closed. The complete batch executes exactly twice without adapter retries and must yield canonical-equivalent snapshots whose ledgers equal the selection ledger. Successful fresh evidence emits only a scoped-v3 reconciliation-plan digest with explicit `query_chronology=selected_prefix_v1`; both historical full-union plan families remain reconstruction-only. Its boundary-local HTTP client never follows redirects. `provider_read_lifecycle` truthfully distinguishes pre-dispatch, attempted-without-response, response received, partial/complete body reads, and captured status; token/config failure is zero provider calls. Every result after fixed-query construction carries a versioned, digest-bound `query_shape_receipt` containing only aggregate counts/presence booleans for ledger, schema catalog, xinfo, FK definition/check, and seed statement classes; it never contains SQL, identifiers, paths, excerpts, or data, while pre-query failures report null. The output-only receipt leaves predecessor query/plan authority unchanged. A duplicate-free, completely read authenticated Cloudflare HTTP error envelope may expose only allowlisted provider code/category pairs (7500 / `d1_error`, 10000 / `authentication_error`); provider messages are always discarded and malformed, partial, oversized, unexpected, or non-allowlisted envelopes remain generic. `effect_assertion_id=schema_create_only_v1` remains the classified CREATE TABLE/INDEX-only contract and rejects views/triggers. `effect_assertion_id=schema_create_tables_indexes_views_triggers_v1` additionally derives exact versioned CREATE VIEW/TRIGGER identities, including trigger parent table and exact `sqlite_master.sql` digest. Trigger parents must be tables in the same selected state; only physical tables require xinfo/FK proof. Trigger bodies retain internal semicolons and nested CASE/END as one statement. `effect_assertion_id=schema_create_objects_additive_v1` preserves that CREATE-object scope and additionally permits at most one canonical unqualified `ALTER TABLE ... ADD [COLUMN]` with a bounded single-column definition plus at most one exact `PRAGMA foreign_keys = ON` per prefix. An optional trailing CHECK is limited by token/depth/list/literal bounds and may reference only the added column through `IS NULL`, literal equality/IN, `length`, `substr`, and `AND`/`OR`; subqueries, other-column references, unknown functions/operators, and other column constraints fail closed. Its parent must exist in the baseline or a strictly earlier prefix; complete ordered xinfo and foreign-key state must be preserved, exactly one classified column must be appended, and the parent's reviewed `sqlite_master.sql` digest must change, binding the full constraint bytes. The PRAGMA is semantic manifest intent only, not evidence of persistent connection state. `effect_assertion_id=schema_create_objects_additive_seed_rows_v1` extends that additive scope with one bounded canonical TEXT/INTEGER seed INSERT per manifest-created table, exact typed row readback, and aggregate-only evidence. The distinct `schema_create_objects_additive_seed_rows_v2` assertion additionally permits canonical SQL NULL only for reviewed nullable columns and binds a version-2 row-set hash, statement class, terminal receipt, and replay identity; v1 remains unchanged. Classified CREATE forms are unconditional, SQLite parent/seed identities are ASCII-case-normalized to the reviewed CREATE spelling, and STRICT tables admit only TEXT-on-TEXT or INTEGER-on-INT/INTEGER non-NULL seed pairs. The three predecessor assertions continue to reject seed INSERTs. Across every assertion, the configured migration-ledger table is a reserved SQLite identifier under ASCII case-insensitive equivalence: no derived CREATE identity or index/trigger parent may collide with it, and additive ALTER cannot target it. Every accepted trigger retains conservative bounded lexical evidence from its complete post-parent header (including `WHEN`) and body: words, quoted identifiers, and string-literal values are compared exactly and case-insensitively, while symbols carry no value. An exact string-literal collision is deliberately rejected; longer unrelated token values remain valid. This is rejected before expectation validation, custody inspection, or provider access, while unrelated triggers remain supported. Successful responses preserve the legacy `effect_assertion.scope.statement_class=schema_create_only` value for `schema_create_only_v1`, and report the closed truthful values `schema_create_tables_indexes_views_triggers`, `schema_create_objects_additive`, `schema_create_objects_additive_seed_rows`, and `schema_create_objects_additive_seed_rows_with_nulls` for the broader assertions; the adjacent `schema_object_types` array reports each selected assertion's complete allowed scope. Temporary/schema-qualified objects, malformed bodies, reused identities, arbitrary top-level DML, non-allowlisted ALTER/PRAGMA, DROP, virtual tables, data-producing CREATE, missing assertions, and unclassified SQL return fail-closed capability evidence. Response buffering stops at 16 MiB, and present read-only metadata must have exact boolean/integer zero types and values. Successful evidence classifies `not_committed`, `partial_state_converged`, or `full_state_converged` as documented atomic-state inference, never provider-attempt causality. Acquired and revalidated evidence reports `lease_retained=true`; pre-acquisition validation/inspection failures and later custody drift report `lease_retained=null` with `not_inspected`, `inspection_failed`, or `retained_evidence_unverified` status as applicable. Custody is revalidated after every attempted provider call, including provider error returns; simultaneous provider failure and custody drift preserves provider classification/evidence while custody remains unverified. Post-read contradictions retain verified custody and exact provider-call counts unless custody itself drifts, and multi-call `response_evidence` is retained in chronological order. HTTP 401, 403, 429, and 5xx responses—including invalid UTF-8, malformed/truncated, or oversized bodies—preserve captured status, are unavailable evidence, and never trigger an automatic retry. Capability gaps, unavailable provider/auth/transport evidence, malformed or unstable results, missing/unexpected schema, SQL-digest/xinfo/FK mismatch, and any FK violation fail closed. This slice cannot retire a lease or persist a terminal reconciliation receipt. |
| `d1_finalize_migration_reconciliation` | All exact `d1_reconcile_migration_manifest` inputs; `expected_reconciliation_plan_sha256`, `expected_expectation_proof_sha256`, `expected_query_sha256`, `expected_canonical_snapshot_sha256`, `expected_outcome`, exact original/current prefix lengths, and distinct `terminal_request_sha256`/`terminal_attempt_sha256` | `migrations_table`, `effect_assertion_id`, `dry_run`, `approved_terminal_plan_sha256` (required live) | Mutating local-custody successor that never issues provider writes. Before provider access, terminal execution independently recomputes the legacy-v1 full-union, historical-v2 effect-assertion full-union, and scoped-v3 selected-prefix reconciliation-plan digests and requires exactly one to match `expected_reconciliation_plan_sha256`; that exact family selects query chronology, after which `expected_query_sha256` and the expected current prefix must reproduce its constructor. Equal query digests do not change chronology, and unknown, ambiguous, or plan/query-inconsistent evidence fails with zero provider calls. The current constructor performs one primary-current selection read and two complete batches. Exact predecessor non-seed evidence performs its historical two full-union batches without selection, while predecessor seed evidence retains its historical selection read. The rederived query SHA-256 and version-1 query-shape receipt then bind the exact target, lease, selected effect-assertion ID, apply/reconciliation/expectation/query/snapshot evidence, outcome/prefixes, and request/attempt identities. Both prefixes must be bounded by the exact supplied manifest: `not_committed` requires current equal to original, `partial_state_converged` requires original less than current less than manifest length, and `full_state_converged` requires original less than current equal to manifest length. The reconciliation response reports the selected ID and exact object-type scope; reconciliation-plan digest, terminal-plan digest, version-2 receipt, success response, and zero-provider-call replay all attest that same ID. Changing it after approval conflicts even when assertions derive identical CREATE-object state; the legacy `schema_create_only_v1` selection remains supported. Receipt reads accept both exact canonical schemas while every new write is version 2: a predecessor version-1 receipt is mapped exclusively to `schema_create_only_v1`, may resume active/retiring custody or replay retirement under its historical plan digests, and can never attest either extended assertion. Both receipt versions reject `not_committed` with unequal prefixes and either converged outcome without strict growth before any manifest is available; finalization and completed replay then enforce the full manifest-bound matrix. The same exact selected effect assertion and its complete CREATE-object plus, when selected, additive transition proof are consumed by read-only reconciliation, terminal dry run, live finalization, and completed-retirement replay. Live execution requires an independently pre-existing exact terminal-plan approval, repeats the complete proof, performs a fresh primary-current/custody read immediately before create-only canonical receipt persistence, repeats it immediately before guarded retirement, and stops without provider retry on any ambiguity or drift. `terminal-reconciliation.<nonce>.receipt.json` is private, canonical, descriptor-bound, unaliased, create-only evidence. Exact incumbent replay converges only after locally reclassifying the supplied manifest, validating its complete typed expectations, and reproducing the receipt-bound legacy-v1, historical-v2 full-union, or scoped-v3 reconciliation plan; input drift fails before provider access. If an exact concurrent caller completes retirement after the initial inspection but before reconciliation preparation, a zero-provider-call preparation failure permits one fresh custody inspection and converges only through that same exact completed-retirement replay. Any provider-dispatched failure remains ambiguous and is never relabelled as replay. Changed fields, duplicate/unknown keys, null/array/primitive/malformed/noncanonical payloads, canonical-but-semantically-contradictory receipts, hard-linked duplicates, conflicting namespaces, and retirement without the exact receipt fail closed with zero provider and local namespace mutations. Retirement uses the held target guard and no-replace active -> retiring -> `retired.<nonce>.lease.json` transitions. Terminal custody fields are evidence claims: only freshly revalidated physical active custody reports `lease_retained=true`, `custody_status=retained_evidence_verified`, and `lease_decision=retain`; pre-inspection, inspection failure, retiring, or unverified/drifted evidence reports `lease_retained=null` with its exact custody status and no lease decision; verified retirement reports `lease_retained=false`, `custody_status=retired_evidence_verified`, and `lease_decision=retired`, including the fail-closed retired-without-receipt case. Once a refresh or read has classified custody as unverified, terminal error handling preserves that negative classification even if a later physical inspection appears restored. An exact replay after complete retirement validates both durable products and returns without provider access. |
| `analytics_engine_list_datasets` | `account_id` unless default account configured | `max_rows` | Lists Workers Analytics Engine datasets by running `SHOW TABLES` through Cloudflare's Analytics Engine SQL API. The SQL API response is returned in its native `FORMAT JSON` shape. Requires an upstream token with Account Analytics Read permission. |
| `analytics_engine_query` | `sql`; `account_id` unless default account configured | `max_rows` | Runs one read-only Workers Analytics Engine SQL statement after the shared restricted-SQL classifier approves it. The SQL is sent as raw text to `/accounts/{account_id}/analytics_engine/sql`, and the SQL API response is decoded in its native `FORMAT JSON` shape rather than the standard Cloudflare v4 envelope. |
| `analytics_engine_describe_schema` | `account_id` unless default account configured | `max_rows` | Lists Analytics Engine datasets with `SHOW TABLES` and returns documented schema/version hints for `dataset`, `timestamp`, `_sample_interval`, `index1`, `blob1`-`blob20`, and `double1`-`double20`, including blob/double/index mapping guidance. |
| `analytics_engine_validate_query` | `sql`; `account_id` unless default account configured | `include_dataset_readback` | Validates one read-only Analytics Engine SQL statement against dataset readback and documented column schema hints without executing that statement. Returns missing dataset and missing column errors separately, reports function calls separately from column references, and includes explicit metadata that the SQL API does not expose a pre-execution query plan. |
| `r2_get_object` | `bucket_name`, `object_key`; `account_id` unless default account configured | `range`, `max_bytes`, `response_mode`, `output_path`, `persist_output_path`, `create_parent_dirs`, `allow_large_download` | Signed private R2 object read/download. `response_mode` is `auto` (default), `text`, `base64`, or `file`. Inline responses are preview-sized (`max_bytes` defaults to 1 KiB and is capped at 256 KiB). `response_mode=file` streams the object directly to `output_path` and returns `bytes_written`, `sha256`, `content_type`, `etag`, and `last_modified`; parent directories are created only when `create_parent_dirs=true`. Set `persist_output_path=true` with `output_path` to save that path locally for future file downloads; the state file defaults to `$XDG_STATE_HOME/cloudflare-mcp/r2-output-path.json` or `$HOME/.local/state/cloudflare-mcp/r2-output-path.json`, and can be overridden with `CLOUDFLARE_MCP_R2_OUTPUT_PATH_STATE_FILE`. `auto` returns inline text only for small UTF-8 objects; binary objects and oversized objects switch to file when an argument or persisted `output_path` is available, otherwise they fail closed with a hint rather than flooding the tool response. Local file downloads over the default large-object threshold require `allow_large_download=true`, `max_bytes`, or `range`. |
| `r2_inspect_object` | `bucket_name`, `object_key`; `account_id` unless default account configured | none | Signed private R2 object metadata inspection using `HEAD`; does not download the object body. |
| `r2_put_object` | `bucket_name`, `object_key`; `account_id` unless default account configured; one of `content_text` or `content_base64` | `content_type`, `metadata`, `dry_run` | Signed private R2 object write using `PUT`; `metadata` maps to `x-amz-meta-*` headers. |
| `pages_deploy_directory` | `project_name`, `directory`; `account_id` unless default account configured | `project_root`, `branch`, `commit_hash`, `commit_message`, `commit_dirty`, `skip_caching`, `dry_run`, `max_files` | Direct-uploads a local Pages output directory. Live apply obtains an upload token, uploads missing assets, sends the required multipart `manifest`, and returns upload counts plus the deployment. `_headers`, `_redirects`, advanced-mode `_worker.js` files, single-module `_worker.js/index.js` directories, and Wrangler-generated multipart `_worker.bundle` files are supported. The directory form is uploaded as the `_worker.js` form part and must contain only a regular `index.js`; multi-module directories fail closed as `pages.worker_directory_unsupported_shape` for Wrangler fallback. For Pages projects with a sibling or ancestor `functions/` directory, the tool runs Wrangler's Pages Functions build with an `_worker.bundle` outfile, includes Wrangler's generated bundle and `functions-filepath-routing-config.json`, and reports `directory.functions.detected`/`included` during dry-run and live apply. Use `project_root` when the build output directory is not inside the Pages project root. `_routes.json` is accepted only when the same artifact includes `_worker.js`, `_worker.bundle`, or a successfully bundled Pages Functions payload; otherwise it fails closed as `pages.routes_without_worker`. A multipart bundle accidentally named `_worker.js` fails closed as `pages.worker_js_contains_multipart_bundle` to avoid Cloudflare parsing a form boundary as JavaScript. If the deployment directory itself contains `functions/`, the tool fails closed as `pages.functions_inside_output_directory`; provide the static output directory such as `dist` instead. |
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
| `workers_upload_script` | `script_name`; `account_id` unless default account configured; exactly one of `script_path`, `script_content`, `script_content_base64`, or `multipart_path` | `main_module`, `metadata`, `content_type`, `create_only`, `dry_run`, `confirmation_token`, `reason` | Uploads a Worker module script or prebuilt multipart bundle through Cloudflare's Worker script endpoint. Dry-run prepares the upload and returns `required_confirmation_token` without calling Cloudflare; visible upload summaries include script/metadata SHA-256 digests and metadata keys, not raw metadata values. Apply requires that token, uploads the script or multipart bundle, then reads back Worker settings and returns `readback_verification`; a different non-empty `main_module` fails closed. For create-only module uploads, a null settings `main_module` is resolved only by exhaustive, stable, etag-bound listing/version-detail evidence; malformed, incomplete, ambiguous, or conflicting evidence fails closed. When `create_only` is true, the apply request sends Cloudflare's atomic `If-None-Match: *` precondition; an existing script returns `workers.upload_create_only_conflict` without overwrite or retry. Timeout, transport, response-read/decoding, retryable 5xx, and success envelopes with a missing or null result return `workers.upload_create_only_outcome_uncertain` with `retryable:false`; read back the Worker and reconcile provider evidence before retrying or claiming creation. The default elicitation configuration treats this as an action-time approval tool. |
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

Manifest-owned and bootstrap-initializer D1 writes use a dedicated one-attempt
HTTP client. It requests identity response encoding, refuses redirects, and
caps the response stream at 16 MiB before UTF-8 and strict-envelope decoding.
A 307/308 is not followed. After dispatch, oversize, unsupported encoding,
stream-read, UTF-8, or decode failure is permanently reconciliation-only:
bounded lifecycle and body digest/size evidence is returned when available,
custody is retained when provable, and automatic replay remains forbidden.
The same evidence survives a valid HTTP 200 outer envelope whose inner D1
result is missing, malformed, or failed; that outcome remains ambiguous and
non-retryable for both bootstrap and generic manifest apply.

Successful `d1_reconcile_migration_manifest` evidence enumerates five closed
`effect_assertion.scope.statement_class` values:
`schema_create_only`, `schema_create_tables_indexes_views_triggers`,
`schema_create_objects_additive`,
`schema_create_objects_additive_seed_rows`, and
`schema_create_objects_additive_seed_rows_with_nulls`. The adjacent
`schema_object_types` array is the complete scope for the selected class.
The NULL-capable class still rejects `NULL` for an `INTEGER PRIMARY KEY` in a
rowid table because SQLite would generate an integer rowid instead of
preserving the asserted NULL.

For D1 migration HTTP-error classification, the outer envelope must have
`success=false`, `result=null`, exactly one allowlisted error object, and no
unexpected members. Its `messages` member may be omitted or be an empty array;
any other shape remains generic. Provider message text is always discarded. A
`sql_byte_offset` is emitted only when the parsed numeric offset is strictly
inside the exact SQL byte string dispatched by that provider call. An offset
equal to or greater than the dispatched SQL byte length is impossible evidence
and is omitted while the allowlisted provider code/category, complete-body
digest, custody, and no-retry semantics remain unchanged.

## Staged D1 catalog evidence contract

The crate contains a side-effect-free, non-routed catalog evidence boundary for
future guarded D1 write composition. Projection version 3 derives one immutable,
target-bound structured fact set from `sqlite_schema` and the
`pragma_foreign_key_list()` table-valued function rather than accepting caller
SQL or a generic provider envelope. Its internal provider-custody adapter
normalizes two physical observations into that exact versioned projection
payload and binds each one to the same canonical target and rederived plan using
four distinct dispatch/read identities preallocated before either request. The
pure verifier cannot authenticate physical dispatch or response EOF by itself
and accepts frames constructed only from this retained adapter custody.

Each provider read is exactly one POST through the existing no-redirect
Cloudflare client. The adapter binds the canonical account/database target,
fixed query and its digest, plan digest, and exact row/byte caps to the request
and response. It reads the raw provider body to EOF under the 4 MiB cap before
the same duplicate-key-rejecting, 32-container JSON decoder used by high-custody
migration reads. In accordance with Cloudflare's [D1 Query API response
contract](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/query/),
it requires explicitly present, typed, empty top-level `errors` and `messages`
arrays and one successful result set shaped as `{meta, results, success}`. The
closed ResponseInfo decoder accepts the official `code`, `message`, optional
`documentation_url`, and optional `source.pointer` shape, but any non-empty
array fails terminally without copying provider text into custody errors or
receipts. It rejects duplicate keys, unknown envelope or ResponseInfo fields,
excessive nesting, missing or malformed envelope arrays, network ambiguity,
partial or oversized bodies, non-2xx status, malformed types, response-binding
drift, identity reuse, and the 1,001-row sentinel without a second attempt or
retry.

Each observation must prove a complete body under the exact 4 MiB byte cap, a
literal `results_truncated=false` under the exact 1,001-row provider cap, and
typed successful primary read-only metadata (`changed_db=false`, `changes=0`,
and `rows_written=0`). The 1,001st row is a completeness sentinel, not catalog
content. Projection rows are a closed typed union of relation, trigger-owner,
schema-auxiliary, schema-blocker, foreign-key, and foreign-key-blocker facts.
The query enumerates every physical `sqlite_schema` row before classification.
It retains the SQLite storage class and uppercase hexadecimal bytes of schema
type, name, and owner fields, plus the SQL storage class. A non-TEXT or otherwise
malformed field therefore becomes an explicit blocker row instead of being
normalized by a cast or omitted by a type predicate. Only unique printable-ASCII
TEXT table names with structurally valid catalog fields are eligible inputs to
`pragma_foreign_key_list()`; blocker names never reach that function.

Foreign-key rows retain native typed id and sequence plus the storage class and
exact bytes of referenced table, `from`, `to`, update action, delete action, and
match mode. `to=NULL` and `to=''` remain distinct. Composite rows require one
parent/action/match identity, unique contiguous sequences beginning at zero,
and exact from/to evidence at every sequence. This matches the semantic field
set used by migration reconciliation without coupling the two implementations.
Relation rows retain SQL bytes only for structurally valid tables and only as a
later AUTOINCREMENT token source. View SQL and trigger bodies are never
projected or interpreted. Missing owners or parents, malformed storage classes,
ambiguous schema identities, unavailable table token sources, and unproven
view/trigger write semantics remain exact conservative blockers.

Rows are keyed by physical schema rowid and fact order and must be strictly
ordered exactly as the fixed query specifies. The 1,001-row sentinel applies to
the complete union, so a late blocker cannot be silently dropped within the
accepted bound. The two payloads must deserialize to equal typed row vectors.
The snapshot digest covers canonical JSON reserialization of that typed vector;
equality of the original provider JSON bytes is neither required nor claimed.

The adapter receipt contains only target/plan/query digests, the SHA-256 and
size of each body completed at EOF, and aggregate counts and caps; raw request
or response content and private dispatch/read identities are omitted. The
adapter does not retain raw provider bodies. Its completed-body digest permits
comparison only when separately authorized bytes are available; it cannot by
itself reauthenticate provider origin or prove EOF independently of the trusted
HTTP adapter lifecycle that issued the receipt. The owned result exposes two
borrowed frames for the pure verifier only after both complete primary read-only
reads pass custody checks. The verifier receipt contains only
target/plan/query/snapshot and observation-pair digests, counts, caps, and body
sizes. The verifier additionally returns an internal opaque product containing
the accepted typed rows; its aggregate-safe receipt counts physical schema rows,
each fact/blocker family, and all conservative blockers without exposing names
or SQL. Neither receipt nor product parses CREATE TABLE text, view SQL, or
trigger bodies; traverses a graph; authorizes DDL, DML, foreign-key effects,
implicit writes, provider admission, custody outside these exact reads, or any
mutation. No public MCP tool currently exposes this staged contract.

## Structured payload details for complex tools

For `effect_assertion_id=schema_create_objects_additive_seed_rows_v1` or its
versioned NULL-capable successor
`schema_create_objects_additive_seed_rows_v2`, every
`d1_reconcile_migration_manifest.state_expectations[]` item includes cumulative
`seed_tables[]` entries with this aggregate-only shape:

```json
{
  "table_name": "channels",
  "columns": ["channel_id", "display_name"],
  "row_count": 3,
  "rows_sha256": "<lowercase SHA-256>"
}
```

Both assertions admit only one plain unqualified `INSERT INTO <table>
(<explicit columns>) VALUES (<bounded canonical literal tuples>)` per
manifest-created table. Version 1 remains byte-for-byte closed to TEXT and
INTEGER literals. Version 2 additionally admits the canonical SQL keyword
`NULL`; it uses the distinct typed row representation
`{"storage_class":"null","value":null}` and version-2 row-set proof domain,
so its `rows_sha256`, reconciliation plan, terminal plan, durable receipt, and
replay identity cannot alias version 1. A NULL literal is admitted only for a
reviewed nullable column that is not an `INTEGER PRIMARY KEY` column in a rowid
table; SQLite would replace such a NULL with a generated rowid. Declared
affinity and STRICT mode do not make a `NOT NULL` column safe. Every classified
CREATE must be unconditional;
`CREATE ... IF NOT EXISTS` is rejected because an incumbent schema object could
turn it into a no-op. CREATE must precede the seed, and every trigger on the
target must follow it across the whole manifest. SQLite ASCII case-insensitive
target matching governs CREATE, ALTER, index, trigger, seed, and reuse
authority, while preserving the reviewed `CREATE TABLE` spelling in exact
expectations and fixed read queries. For a baseline table not created by the
manifest, derivation instead selects the first encountered manifest parent
spelling for each SQLite ASCII identity; transition matching is case-insensitive,
while the provider and expectation spelling remains unchanged in the fixed
proof. Non-NULL expected storage is admitted only when it
is identity-stable under the reviewed SQLite affinity: for non-STRICT tables,
TEXT literals on TEXT/BLOB affinity and INTEGER literals on
INTEGER/NUMERIC/BLOB affinity; for STRICT tables, only TEXT literals on exact
TEXT columns and INTEGER literals on exact INT/INTEGER columns. STRICT BLOB and
other unproven non-NULL literal/type pairs fail before custody or provider
access. NULL with a non-null provider value, non-NULL storage with a JSON null
value, and every other malformed storage-class/value pairing fail closed. The
tool performs one
primary-current prefix-selection read before two identical complete
primary-current reads. Each complete read queries the bounded full-manifest
`sqlite_master` object union, while safe table-valued PRAGMAs cover only the
exact physical tables in the selected prefix. This detects premature future
objects without probing a future table that does not yet exist. Object
membership uses SQLite ASCII `NOCASE` identity while exact observed spelling
and canonical type/name ordering are retained; aliases or conflicting spellings
fail closed. Seed-row SELECTs remain selected-prefix and existence-aware. A
full-manifest registry binds every seed target to its CREATE and INSERT
prefixes: a selected prefix before CREATE does not run a seed-row SELECT from
that table, a prefix after CREATE but before INSERT proves the exact zero-row
table projection without requiring a column added by a later prefix, and a
prefix at or after INSERT proves the exact typed row set. An unexpected row in
the zero-row window fails on the first complete proof, before a second complete
read and without provider or local mutation. Terminal dry run and finalization
rederive the registry and repeat the same selected-prefix proof. Neither
complete response may choose another
ledger prefix: both complete ledgers must exactly equal the initial selected
ledger, while the two complete snapshots must also remain canonically equal to
each other. Aggregate-safe `selection_binding` reports only the selection-query
digest, selected-ledger digest and prefix length, and both complete-ledger
digests. Each provider response is parsed locally and then retained lease
custody is freshly revalidated before either a successful snapshot or a parse
failure may claim verified custody. It compares storage class and canonical
value locally and returns only table/column identity, exact row count, and the
row-set digest. Arbitrary DML, conflict clauses, expressions, implicit columns,
qualified identifiers, unsupported storage classes, duplicates, ordering
violations, and any row-set mismatch fail closed. Reconciliation, terminal
planning, version-2 receipts, and zero-provider-call replay bind the selected
assertion and the same expectation proof. Predecessor assertions remain closed
to top-level INSERT.

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
accepted by Cloudflare's Worker script settings endpoint; the MCP input schema
rejects non-object JSON before the curated mutation path runs. Its apply path
sends Cloudflare's required `multipart/form-data` `settings` part, then reads
back the settings. For binding verification, pass `expect_binding`:

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
different `main_module` than the requested upload. For create-only module
uploads, Cloudflare settings may legitimately omit `main_module`; the tool
then requires an authenticated listing, exactly one initial version, and
version-detail `resources.script` evidence whose etag matches the upload
response and whose handler shape is valid with byte-exact, nonblank handler
names and export members. The version inventory must be
exhaustively paginated from the endpoint's outer `result_info` metadata and
stable across a second read; an optional nested `pagination` object must agree
with it when present. Ambiguous, malformed,
conflicting, incomplete, or missing version evidence fails closed. Multipart bundle uploads
report module-name readback verification as not applicable because the bundle
owns its module graph.

## Mutating call requirements

For all mutating tools (`api_mutate`, `account_api_tokens`, `r2_put_object`, `ensure_tunnel`, `connector_control`, `upsert_dns_cname`, `upsert_access_app`, `replace_access_policies`, `apply_access_allowlist`, `patch_worker_settings`, `workers_upload_script`, `waf_ruleset_apply_change`, `cache_purge`, `cache_zone_setting`, `cache_rules`, `cache_reserve`, `cache_tiered`, `cache_variants`, `cache_origin_regions`, `lock_first_publish`, `emergency_unpublish`, `portal_agent_request`):

- Run once with `dry_run=true` before apply.
- Send `x-correlation-id` for audit traceability.
- Expect `plan` and `audit` in response payloads.
- In read-only mode (`CLOUDFLARE_MCP_READ_ONLY=1`), mutating tools are not callable (`method_not_found`).
- In curated-tools-only mode (`CLOUDFLARE_MCP_API_PARITY_ENABLED=0`), generic API parity tools (`api_parity_status`, `api_find_operations`, `api_get_operation`, `api_prepare_call`, `api_read`, `api_mutate`) are hidden and not callable.
- If elicitation is enabled and the tool is configured as dangerous, expect approval prompts before apply execution.
- Broad cache actions add local confirmation: `cache_purge` with `payload.everything=true` and `cache_rules` with `action=replace_all` require echoing the token returned by dry-run. `workers_upload_script` also requires echoing the dry-run token for apply because it deploys executable Worker code. `waf_ruleset_apply_change` requires the token returned by `waf_ruleset_plan_change` because WAF action, ordering, list, and cap mistakes can affect production traffic.
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
