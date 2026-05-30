# Cloudflare API Parity

This server provides broad Cloudflare REST API v4 parity through an
OpenAPI-derived operation catalog plus guarded generic executor tools.

Cloudflare also provides an official hosted MCP server for broad API access.
Use that server when the goal is general-purpose Cloudflare API reach with
minimal tool context. This server keeps a generic REST executor as a guarded
fallback for self-hosted operator workflows, while curated tools remain the
preferred path for safety-sensitive operations.

## Parity model

- Source of truth: Cloudflare's official OpenAPI schema at
  `https://raw.githubusercontent.com/cloudflare/api-schemas/main/openapi.json`.
- Runtime source: committed compact catalog at
  `spec/cloudflare_api_catalog.v1.json`.
- Scope: Cloudflare REST API v4 operations that use the standard Cloudflare API
  envelope and bearer token authentication.
- Product workflows with curated safety policy remain specialized tools. D1
  workflows use `d1_list_databases`, `d1_get_database`, `d1_inspect_schema`,
  `d1_query_read_only`, `d1_validate_query`, `d1_execute_write`,
  `d1_apply_migrations`, `d1_rename_database`, and `d1_delete_database`;
  Workers Analytics Engine workflows use
  `analytics_engine_list_datasets`, `analytics_engine_describe_schema`,
  `analytics_engine_validate_query`, and `analytics_engine_query`; R2
  S3-compatible object access uses `r2_get_object`, `r2_inspect_object`, and
  `r2_put_object`; future GraphQL-specific coverage should be added
  separately.

The server intentionally does not register one MCP tool per Cloudflare endpoint.
Instead, clients search and inspect operations before calling the generic
executor:

1. `api_find_operations` to discover operation IDs.
2. `api_get_operation` to inspect parameters, risk, and preferred curated tool.
3. `api_prepare_call` when an agent has search terms and wants exact
   `api_read`/`api_mutate` arguments without manually copying an operation ID.
4. `api_read` for `GET` operations.
5. `api_mutate` for `POST`, `PUT`, `PATCH`, or `DELETE` operations.

Set `CLOUDFLARE_MCP_API_PARITY_ENABLED=0` for curated-tools-only profiles. In
that mode, all generic `api_*` parity tools are hidden and denied, while curated
first-class tools remain governed by the usual read-only/auth policy.

## Safety policy

Use curated tools when `api_get_operation` reports `preferred_tool`; those tools
encode workflow-specific policy, dry-run shape, and readback validation.

`api_mutate` is always guarded:

- `dry_run=true` emits a request plan and confirmation token with no Cloudflare
  side effects.
- apply requires echoing that confirmation token in `confirmation_token`.
- high-risk denied operations fail closed in the generic executor.
- read-only mode exposes `api_read` but denies `api_mutate`.
- when RMCP elicitation is enabled, `api_mutate` is mandatory-gated even if omitted from `CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS`.
- valid escaped JSON-string bodies are normalized into real JSON before dry-run
  planning, token calculation, and apply. Dry-run output includes
  `body_normalized_from_json_string`.
- invalid JSON strings remain strings. Do not apply those to endpoints that
  require object request bodies; rerun dry-run with a valid object body first.

Denied-by-default categories include account deletion, billing/payment,
registrar purchase/delete/transfer, API token/key management, membership/role
management, zone deletion, and similar account-level destructive operations.

## Catalog refresh

Refresh the catalog only as an intentional contract change:

```bash
tools/generate-api-catalog.sh
```

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
