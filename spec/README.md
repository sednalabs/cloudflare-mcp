# Tool Contract Workflow

Related docs:
- `../README.md` for operator/client setup and runtime behavior.
- `../docs/CLIENT-CONTRACT.md` for explicit per-tool request argument expectations.
- `../docs/RUNBOOK.md` for rollout sequencing and safety gates.

This server uses a committed tool schema contract snapshot at:

- `spec/tool_schema_snapshot.v1.json`

It also uses a committed Cloudflare REST API parity catalog at:

- `spec/cloudflare_api_catalog.v1.json`

The parity catalog is generated from Cloudflare's official OpenAPI schema
(`https://raw.githubusercontent.com/cloudflare/api-schemas/main/openapi.json`).
Refresh it only as an intentional contract update, then review the source hash,
operation count, risk classifications, and curated `preferred_tool` mappings.
Use `tools/generate-api-catalog.sh` for the refresh.

Use this workflow for intentional tool-surface changes:

1. Implement the tool change.
2. Run contract test to confirm drift:
   - `cargo test tools::tests::tool_schema_snapshot_contract_is_stable`
3. If drift is intentional, regenerate snapshot:
   - `MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test tools::tests::tool_schema_snapshot_contract_is_stable`
4. Re-run full validation:
   - `cargo test`
   - `cargo test --test mcp_stdio_smoke`
5. Review snapshot diff and ensure it matches the intended API change before merge.

This keeps accidental tool schema drift out of CI while allowing explicit, reviewed updates.
The snapshot is only the inventory/schema contract. For any tool that is added,
restored, hidden, or behaviorally changed, add or update MCP stdio smoke
coverage so the executable is called through JSON-RPC and rmcp extraction errors
cannot hide behind direct Rust handler tests.

When changing tool argument shape or required fields, update both:
- `spec/tool_schema_snapshot.v1.json` (machine contract),
- `../docs/CLIENT-CONTRACT.md` (human-readable client contract).

When changing generic API parity behavior, update:
- `spec/cloudflare_api_catalog.v1.json` when the official API source changes,
- `../docs/CLIENT-CONTRACT.md` for client-visible tool behavior,
- `../docs/API-PARITY.md` for parity policy and workflow changes.
- `../tests/mcp_stdio_smoke.rs` when behavior depends on MCP argument extraction,
  arbitrary JSON bodies, dry-run planning, or stdio context.

Generic REST executor path parameters are derived from the URL template in
addition to the compact catalog's `path_params` field. If a generated catalog
entry omits a placeholder such as `{account_id}`, the executor must still render
that placeholder from explicit arguments or configured defaults. Keep a stdio
regression when fixing this class of catalog drift.

Cloudflare Analytics GraphQL is not part of the REST catalog. Use the curated
`graphql_analytics_query` tool for read-only `/client/v4/graphql` analytics
queries and `account_billing_usage` for billing/usage REST records.

Note on read-only mode:
- `CLOUDFLARE_MCP_READ_ONLY=1` intentionally filters tool exposure at runtime.
- The snapshot remains the canonical full tool contract; runtime policy decides which tools are visible/callable.

Note on elicitation mode:
- `CLOUDFLARE_MCP_ELICITATION_ENABLED=1` adds runtime approval gates for configured dangerous calls.
- `account_api_tokens` and `api_mutate` are mandatory-gated when elicitation is enabled; token read actions bypass approval.
- `account_api_token_permission_plan` is read-only and returns a safe
  `account_api_tokens` update dry-run payload for permission deltas; it does
  not mutate token scopes itself.
- This does not change tool argument schemas; it changes pre-execution policy behavior.

Preserved curated tool families:
- D1 read tools (`d1_list_databases`, `d1_get_database`, `d1_inspect_schema`, `d1_query_read_only`, `d1_validate_query`) are first-class contract tools and must remain present even when broad API parity is available.
  `d1_inspect_schema` supports targeted `include_tables`/`include_table_pattern`
  filtering and must keep Cloudflare internal `_cf_*` objects out of
  application `column_errors`.
- Workers Analytics Engine read tools (`analytics_engine_list_datasets`, `analytics_engine_query`, `analytics_engine_describe_schema`, `analytics_engine_validate_query`) are first-class contract tools for Account Analytics Read workflows and must remain present even when broad API parity is available.
- Queues readback tools (`queues_list`, `queues_get`, `queues_get_metrics`, `queues_list_consumers`, `queues_health`) are first-class contract tools and must remain present for operational backlog/DLQ/consumer diagnostics.
