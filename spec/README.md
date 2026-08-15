# Tool Contract Workflow

Related docs:
- `../README.md` for operator/client setup and runtime behavior.
- `../docs/CLIENT-CONTRACT.md` for explicit per-tool request argument expectations.
- `../docs/RUNBOOK.md` for rollout sequencing and safety gates.
- `../docs/CONFORMANCE_DOGFOOD.md` for the MCP Toolkit dogfood matrix and
  where to add large-catalog/tool-search/deferred-loading regressions.

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
   - `cargo build --release`
   - `scripts/generate-release-provenance.sh --binary target/release/cloudflare-mcp --output .tmp/release-provenance.json`
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

The release provenance manifest complements the schema snapshot. The snapshot
proves the committed tool schemas; the manifest ties a built binary to the
source commit, normalized `--print-tools` inventory hash, schema/catalog hashes,
binary SHA-256, and pinned `mcp-toolkit-rs` revision. Use both before relying on
an installed binary for production-like operations.

Generic REST executor path parameters are derived from the URL template in
addition to the compact catalog's `path_params` field. If a generated catalog
entry omits a placeholder such as `{account_id}`, the executor must still render
that placeholder from explicit arguments or configured defaults. Keep a stdio
regression when fixing this class of catalog drift.

Cloudflare Analytics GraphQL is not part of the REST catalog. Use the curated
`graphql_analytics_query` tool for read-only `/client/v4/graphql` analytics
queries and `account_billing_usage` for billing/usage REST records. GraphQL and
curated WAF analytics responses may now include
`diagnostics.authz_classification` when the MCP can distinguish likely cause
classes such as invalid token, wrong account or zone context, grouped paths
blocked while raw paths still work, or likely entitlement or product
restriction.

Note on read-only mode:
- `CLOUDFLARE_MCP_READ_ONLY=1` intentionally filters tool exposure at runtime.
- The snapshot remains the canonical full tool contract; runtime policy decides which tools are visible/callable.

Note on elicitation mode:
- `CLOUDFLARE_MCP_ELICITATION_ENABLED=1` adds runtime approval gates for configured dangerous calls.
- `account_api_tokens` and `api_mutate` are mandatory-gated when elicitation is enabled; token read actions bypass approval.
- `account_api_token_permission_plan` is read-only and returns a safe
  `account_api_tokens` update dry-run payload for permission deltas; it does
  not mutate token scopes itself.
- `api_mutate` enforces the named Bot Management zone-update permission
  preflight: fresh `token_permissions` must contain both `Bot Management Write`
  and `Zone Settings Write` before the dry-run exposes a confirmation token.
  Missing or unverified permissions return guarded token inspection and repair
  calls instead of an interactive-login recommendation.
- Apart from the explicit `api_mutate.token_permissions` field above,
  elicitation does not alter tool argument schemas; it changes pre-execution
  policy behavior.

Preserved curated tool families:
- D1 read tools (`d1_list_databases`, `d1_get_database`, `d1_inspect_schema`, `d1_query_read_only`, `d1_validate_query`) are first-class contract tools and must remain present even when broad API parity is available.
  `d1_inspect_schema` supports targeted `include_tables`/`include_table_pattern`
  filtering and must keep Cloudflare internal `_cf_*` objects out of
  application `column_errors`.
- Retained-manifest reconciliation (`d1_reconcile_migration_manifest`) is a
  first-class read-only D1 recovery contract. Keep its exact structured
  expectation schema, manifest-derived complete prefix inventory, query-bound
  statement markers, bounded streaming, truthful custody classification, and
  real MCP stdio negative/no-retry/no-custody-mutation proof aligned with the
  snapshot. `schema_create_only_v1` is the stable table/index assertion;
  `schema_create_tables_indexes_views_triggers_v1` is the explicit extended
  assertion. The latter must preserve exact type/name/parent/SQL-digest proof
  for every view and trigger without issuing table PRAGMAs for those objects,
  and must keep trigger-body semicolons plus nested `CASE ... END` inside one
  fail-closed classified statement.
  `schema_create_objects_additive_v1` is the separate closed additive
  assertion: it retains the extended CREATE proof, adds one bounded unqualified
  ADD COLUMN transition and semantic `PRAGMA foreign_keys = ON` intent per
  prefix, and requires exact ordered before/after xinfo, foreign-key, and parent
  SQL-digest evidence. Its optional trailing CHECK is a bounded column-local
  pure expression over literal equality/IN, `IS NULL`, `length`, `substr`, and
  `AND`/`OR`; other identifiers, functions, constraints, and SQL effects fail
  before custody. It never executes manifest SQL or treats connection
  PRAGMA state as persistent evidence. The predecessor assertions remain
  byte-for-byte behaviorally closed to ALTER and PRAGMA.
  `schema_create_objects_additive_seed_rows_v1` is the distinct canonical
  seed-row assertion. It extends the additive scope with one bounded,
  unqualified `INSERT INTO <manifest-created-table> (<explicit columns>)
  VALUES (<literal tuples>)` per target table. Only canonical TEXT and signed
  INTEGER literals are admitted. Every classified CREATE is unconditional;
  `IF NOT EXISTS` is rejected. CREATE must precede the seed and every trigger
  on that table must follow it, including across manifest entries. Each prefix
  supplies the exact table, ordered columns, row count, and aggregate row-set
  SHA-256. SQLite ASCII case variants share one CREATE, ALTER, index, trigger,
  and seed target and the reviewed CREATE spelling. Baseline tables not created
  by the manifest use the first encountered manifest parent spelling for
  case-insensitive transition derivation while retaining exact provider and
  expectation spelling in the fixed proof. Non-STRICT tables admit
  only identity-stable TEXT/BLOB and INTEGER/NUMERIC/BLOB literal affinity
  pairs. STRICT tables admit only TEXT-on-TEXT and INTEGER-on-INT/INTEGER pairs;
  STRICT BLOB seeds fail before custody/provider access. A primary-current
  selection read chooses the manifest prefix before two complete
  primary-current proofs. A full-manifest registry omits seed-table reads before
  CREATE, proves exact table emptiness after CREATE and before INSERT without
  referencing future columns, and reads the exact typed rows at or after INSERT.
  Each complete proof ledger must equal the exact initial selected ledger, and
  the two complete snapshots must remain canonically equal to each other; two
  equal complete responses at another prefix fail closed. Aggregate-safe
  selection-query and ledger digests bind this relationship. Terminal
  reconciliation rederives and repeats that selected-prefix proof;
  responses expose only aggregate summaries. Arbitrary DML, expressions, implicit columns,
  conflict clauses, reused targets, and malformed or mismatched rows fail closed.
  The three predecessor assertions remain closed to top-level INSERT effects.
  Successful evidence keeps the legacy `schema_create_only` statement-class
  label only for the legacy assertion; the extended and additive assertions
  report `schema_create_tables_indexes_views_triggers` and
  `schema_create_objects_additive`, while the seed assertion reports
  `schema_create_objects_additive_seed_rows`, each with its complete closed
  object/operation array.
  Every assertion also treats the configured migration-ledger table as a
  reserved SQLite identifier: case variants in CREATE identities, index or
  trigger parents, any exact admitted trigger header/body lexical token, and additive
  ALTER targets fail before custody/provider access.
  The conservative bounded evidence includes words, quoted identifiers, and
  string-literal values across the complete post-parent header (including
  `WHEN`) and body. Exact string-literal collisions therefore fail closed;
  longer unrelated token values and unrelated triggers remain valid.
- Terminal retained-manifest reconciliation
  (`d1_finalize_migration_reconciliation`) is the separately approval-gated
  local-custody mutation contract. Keep its exact evidence/request/attempt
  binding, create-only canonical receipt, fresh primary-current checks,
  no-provider-write behavior, guarded retirement, truthful custody-state
  products, restored negative matrix, and completed exact replay aligned across
  schema, stdio proof, and runbook. Only freshly verified active custody may
  claim retained/retain; unknown, uninspected, failed-inspection, or retiring
  states must not fabricate that authority.
  Canonical v1/v2 receipt parsing must reject semantic contradictions without a
  manifest: `not_committed` means equal original/current prefixes, while either
  converged outcome requires strict prefix growth. New finalization and
  completed-retirement replay must additionally bind both prefixes to the exact
  supplied manifest: partial convergence ends strictly before manifest length
  and full convergence ends exactly at it. Every rejected outcome/prefix or
  out-of-bounds product has zero provider and local namespace mutations.
- Workers Analytics Engine read tools (`analytics_engine_list_datasets`, `analytics_engine_query`, `analytics_engine_describe_schema`, `analytics_engine_validate_query`) are first-class contract tools for Account Analytics Read workflows and must remain present even when broad API parity is available.
- Queues readback tools (`queues_list`, `queues_get`, `queues_get_metrics`, `queues_list_consumers`, `queues_health`) are first-class contract tools and must remain present for operational backlog/DLQ/consumer diagnostics.
