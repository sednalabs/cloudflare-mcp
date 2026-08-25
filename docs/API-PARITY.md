# Cloudflare API Parity

This server provides broad Cloudflare REST API v4 parity through an
OpenAPI-derived operation catalog plus guarded generic executor tools.

Cloudflare also provides an official hosted Code Mode MCP server for broad API
access. Both surfaces can reach a large part of the Cloudflare API, but "broad
coverage" should not be mistaken for the same architecture or trust model.

Use Cloudflare's hosted API MCP when the goal is general-purpose, current
Cloudflare API reach with minimal tool context. Use this server's generic REST
fallback when the operation belongs inside a self-hosted operator session and
must remain subject to the local read-only, deny, confirmation, approval, or
audit boundary.

See [OFFICIAL_MCP_COMPARISON.md](OFFICIAL_MCP_COMPARISON.md) for the detailed
comparison.

## Parity model

- Source of truth: Cloudflare's official OpenAPI schema at
  `https://raw.githubusercontent.com/cloudflare/api-schemas/main/openapi.json`.
- Runtime source: committed compact catalog at
  `spec/cloudflare_api_catalog.v1.json`.
- Scope: Cloudflare REST API v4 operations that use the standard Cloudflare API
  envelope and bearer token authentication.
- Freshness boundary: the runtime does not fetch an unreviewed moving OpenAPI
  schema on every request. New upstream endpoints appear here only after an
  intentional catalog refresh and repository change.
- Product workflows with curated safety policy remain specialized tools. D1
  workflows use `d1_list_databases`, `d1_get_database`, `d1_inspect_schema`,
  `d1_query_read_only`, `d1_validate_query`, `d1_execute_write`,
  `d1_apply_migrations`, `d1_bootstrap_migration_ledger`,
  `d1_reconcile_bootstrap_migration_ledger`,
  `d1_finalize_bootstrap_migration_ledger`,
  `d1_apply_migration_manifest`, `d1_reconcile_migration_manifest`,
  `d1_finalize_migration_reconciliation`, `d1_rename_database`, and
  `d1_delete_database`; Workers Analytics Engine workflows use
  `analytics_engine_list_datasets`, `analytics_engine_describe_schema`,
  `analytics_engine_validate_query`, and `analytics_engine_query`; R2
  S3-compatible object access uses `r2_get_object`, `r2_inspect_object`, and
  `r2_put_object`; account billing usage uses `account_billing_usage`; Cloudflare
  Analytics GraphQL uses `graphql_analytics_query`.

The server intentionally does not register one MCP tool per Cloudflare endpoint.
Instead, clients search and inspect operations before calling the generic
executor:

1. `api_find_operations` to discover operation IDs.
2. `api_get_operation` to inspect parameters, risk, and preferred curated tool.
3. `api_prepare_call` when an agent has search terms and wants exact
   `api_read`/`api_mutate` arguments without manually copying an operation ID.
4. `api_read` for `GET` operations.
5. `api_mutate` for `POST`, `PUT`, `PATCH`, or `DELETE` operations.

`api_prepare_call`, `api_read`, and `api_mutate` derive path parameters from the
endpoint template as well as the compact catalog metadata. If the upstream
OpenAPI snapshot omits `path_params` for a path such as
`/accounts/{account_id}/...`, the executor still substitutes the configured
default or explicit path parameter instead of sending literal braces.

Set `CLOUDFLARE_MCP_API_PARITY_ENABLED=0` for curated-tools-only profiles. In
that mode, all generic `api_*` parity tools are hidden and denied, while curated
first-class tools remain governed by the usual read-only/auth policy.

## Relationship to Cloudflare Code Mode

Cloudflare's official Code Mode MCP uses a different solution to the large-API
problem. Its default public interface exposes a very small set of tools and lets
the agent write JavaScript that searches the current API spec and calls
`cloudflare.request()` from an isolated Worker execution environment.
Cloudflare's upstream README advertises roughly 2,500 API endpoints behind that
small Code Mode surface.

Cloudflare can disable Code Mode with `?codemode=false`; in that mode the
managed server registers individual endpoint tools derived from the API schema.
That is closer to traditional endpoint-per-tool MCP, but with a much larger
schema/context footprint.

This repository deliberately chooses neither form for its generic fallback:

- it does not expose thousands of endpoint tools;
- it does not execute caller-supplied JavaScript;
- the operation must exist in the committed catalog;
- the server builds the provider request itself;
- the local mutation policy remains in force.

The tradeoff is explicit: Cloudflare's hosted server wins on immediate upstream
freshness and very broad discovery, while this repository accepts an intentional
catalog-refresh step in exchange for a reviewable local operation catalog and
operator policy boundary.

## Billing and analytics

For usage-spike investigations, start with `account_billing_usage` when the
question is "what is Cloudflare billing or usage recording?" Then use
`graphql_analytics_query` for product attribution, such as D1 rows read/written
by database, date, or query-insights dataset. Cloudflare's Analytics GraphQL API
is a single `/client/v4/graphql` endpoint rather than a REST catalog operation,
so it intentionally has a curated read-only tool instead of being forced through
`api_read`.

Cloudflare's managed GraphQL and product-specific analytics MCPs may be a better
first step for exploratory analytics. Use the local curated tool when the
analysis is already inside this operator boundary or the returned shape is part
of a known operational workflow.

## Safety policy

Use curated tools when `api_get_operation` reports `preferred_tool`; those tools
encode workflow-specific policy, dry-run shape, and readback validation.

`api_mutate` is always guarded:

- `dry_run=true` emits a request plan and confirmation token with no Cloudflare
  side effects.
- apply requires echoing that confirmation token in `confirmation_token`.
- high-risk denied operations fail closed in the generic executor.
- read-only mode exposes `api_read` but denies `api_mutate`.
- when RMCP elicitation is enabled, `api_mutate` is mandatory-gated even if
  omitted from `CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS`.
- valid escaped JSON-string bodies are normalized into real JSON before dry-run
  planning, token calculation, and apply. Dry-run output includes
  `body_normalized_from_json_string`.
- invalid JSON strings remain strings. Do not apply those to endpoints that
  require object request bodies; rerun dry-run with a valid object body first.

Denied-by-default categories include account deletion, billing/payment,
registrar purchase/delete/transfer, API token/key management, membership/role
management, zone deletion, and similar account-level destructive operations.
The generic `worker-script-put-content` operation is also denied: use the curated
`workers_upload_script` flow, which binds its upload digest to dry-run
confirmation and post-upload readback instead of treating executable code upload
as a raw REST body.

The generic `d1-query-database`, `d1-raw-database-query`,
`d1-import-database`, and `d1-time-travel-restore` operations are likewise
denied before request construction or provider access. Query and raw bodies can
mutate schema outside the curated policy boundary; import and restore can
replace existing-target schema and data wholesale. Use the curated D1 read,
row-write, bootstrap, and migration-manifest tools where they cover the task.
Import and time-travel restore require a separately governed curated lifecycle;
they are not redirected to a nonexistent preferred tool. Create, get, list,
export, and metadata updates retain their existing catalog policy, while delete
retains its separate curated high-risk lifecycle.

Cloudflare's provider-side token/OAuth permissions remain the outer authority
boundary. These local controls are defence in depth and workflow admission, not
a substitute for least privilege.

## Catalog refresh

Refresh the catalog only as an intentional contract change:

```bash
tools/generate-api-catalog.sh
```

Use the official Code Mode API MCP when a task needs an upstream operation that
has not yet landed in the committed catalog. If that operation is going to
become part of a recurring safety-sensitive production workflow, prefer to
refresh the catalog and/or add a curated local lifecycle before making it a
normal apply path.

After any catalog or tool-surface change, run:

```bash
cargo test
cargo test --test mcp_stdio_smoke
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test tools::tests::tool_schema_snapshot_contract_is_stable
cargo test tools::tests::tool_schema_snapshot_contract_is_stable
CLOUDFLARE_MCP_AUTH_MODE=off cargo run -- --print-tools
```

The stdio smoke test is part of the parity contract. It exercises the compiled
MCP binary through JSON-RPC instead of calling Rust handlers directly, so it
catches rmcp argument extraction and context-extension regressions.
