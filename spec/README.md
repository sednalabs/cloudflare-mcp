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
- Generic `api_mutate` denies the complete existing-target D1 mutation
  inventory before request construction or provider access:
  `d1-delete-database`, `d1-export-database`, `d1-import-database`,
  `d1-query-database`, `d1-raw-database-query`,
  `d1-time-travel-restore`, `d1-update-database`, and
  `d1-update-partial-database`. Query/raw SQL, rename and delete delegate to
  their named curated tools. Export, import, restore and full metadata update
  remain denied until a governed curated lifecycle exists. D1 create is not an
  existing-target mutation; GET operations remain read-only catalog calls.
- Apart from the explicit `api_mutate.token_permissions` field above,
  elicitation does not alter tool argument schemas; it changes pre-execution
  policy behavior.

Preserved curated tool families:
- D1 read tools (`d1_list_databases`, `d1_get_database`, `d1_inspect_schema`, `d1_query_read_only`, `d1_validate_query`) are first-class contract tools and must remain present even when broad API parity is available.
  `d1_inspect_schema` supports targeted `include_tables`/`include_table_pattern`
  filtering and must keep Cloudflare internal `_cf_*` objects out of
  application `column_errors`.
- Existing-target identity is one strict account/database path-segment
  grammar. Every curated provider mutation validates it before hashing,
  planning or dispatch. Whitespace, NUL, dot, slash, backslash,
  percent-encoded and other noncanonical aliases fail closed. Rename, delete
  and row-write hold the same permanent account/database `guard.lock` used by
  bootstrap and manifest leases. The legacy directory migration apply is
  read-only/retired; local reconciliation finalizers do not send provider D1
  mutations.
- The first-ledger bootstrap (`d1_bootstrap_migration_ledger`) is a distinct
  mutating contract from manifest apply. Keep its exact empty-target dry-run
  digest, shared target custody, one-initializer maximum, no-retry ambiguity,
  stable canonical-schema/empty-ledger readback, one-attempt/no-redirect bounded
  read client, a separate one-attempt/no-redirect migration-write client with a
  16 MiB identity-response stream cap, window/phase/query-bound
  response/lifecycle evidence including
  no-body events, privacy-safe reconciliation-only nested causes for reads and
  initializer failure, physical provider-call and
  mutation accounting, and MCP stdio negative-path coverage aligned with the
  snapshot. It must never become
  a compatibility path for application-bearing or partially initialized D1
  databases.
- Manifest-owned provider writes use that same dedicated write boundary: no
  redirects or adapter retry, identity response encoding, a 16 MiB streamed
  response cap before UTF-8/strict-envelope decoding, truthful pre-dispatch
  versus attempted lifecycle evidence, and permanent reconciliation-only
  handling after any dispatched oversize/read/decode failure. A valid HTTP 200
  outer envelope with missing, malformed, or failed inner D1 results preserves
  the complete response digest, size, and attempted lifecycle while remaining
  ambiguous and non-retryable.
- Bootstrap recovery (`d1_reconcile_bootstrap_migration_ledger`,
  `d1_finalize_bootstrap_migration_ledger`, and
  `d1_abort_bootstrap_migration_ledger`) is its own retained-custody
  contract. Keep the fixed bootstrap family, exact bootstrap-plan/initializer/
  installed-schema authority, two stable primary before/after proof windows made
  from exact one-attempt/no-redirect reads with response-byte evidence,
  canonical empty-ledger-only success, explicit conflict/unknown products,
  create-only terminal receipt, fresh proof before guarded retirement, zero
  provider writes, exact provider-dispatch and local mutation accounting, no
  initializer retry, and zero-call completed replay aligned across schema, stdio
  tests, and runbook. Custody drift must erase stale retention claims while
  preserving known receipt state. An empty manifest must never substitute for
  this authority. The abort path is separately limited to marker-aware custody
  with stable physical absence of the mandatory pre-dispatch initializer
  attempt receipt; it must reject legacy, malformed, contradictory, present,
  or unstable marker evidence and preserve permanent no-retry semantics after
  any attempted or ambiguous initializer.
- The exact `migration-ledger-bootstrap-v1` family is reserved to that
  dedicated bootstrap lifecycle. Generic manifest apply, reconciliation, and
  terminal finalization/replay must reject it before provider, custody,
  receipt, or local namespace activity; the reservation is exact rather than
  prefix-based.
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
  The exact leading source bytes `PRAGMA foreign_keys = ON;\n\n` are a separate
  versioned execution concern: the source manifest remains unchanged, while
  `drop-leading-pragma-foreign-keys-on-v1` commits its identity/version, exact
  executed-byte digest, and full provider-statement digest into a version-2
  apply plan. The approved plan digest is the transitive authority carried by
  lease custody, retained reconciliation, terminal receipt/finalization, and
  replay. Near matches, duplicates, embedded occurrences, transform drift, and
  source/receipt mismatch must stop new plan/apply before provider or local
  namespace effects. Exact retained predecessor version-1 plans remain
  read-only reconcilable under the unchanged assertion grammars and cannot
  authorize fresh execution. Identity-only manifests preserve the predecessor
  version-1 plan digest.
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
  `schema_create_objects_additive_seed_rows_v2` is a separate assertion, not a
  widening or relabeling of v1. It adds only canonical SQL `NULL` literals to
  the v1 seed grammar and reports the distinct
  `schema_create_objects_additive_seed_rows_with_nulls` statement class. Its
  typed row-set digest uses version 2 and represents each NULL cell exactly as
  `{"storage_class":"null","value":null}`; storage-class/value
  contradictions fail closed. A reviewed target column must be nullable, and
  NULL is rejected for an `INTEGER PRIMARY KEY` in a rowid table because SQLite
  would replace that literal with a generated rowid rather than preserve the
  asserted NULL. Reconciliation, terminal dry run, live finalization, durable
  receipt authority, and exact completed replay all remain bound to the v2
  assertion identity and its version-2 digest domain. The v1 query, digest,
  receipt, and replay identities remain unchanged.
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
