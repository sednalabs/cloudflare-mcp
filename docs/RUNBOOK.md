# Operator Runbook

This runbook describes the safe operating sequence for `cloudflare-mcp`.

Companion docs:

- [../README.md](../README.md): project overview and quick start.
- [GETTING_STARTED.md](GETTING_STARTED.md): build, run, and first checks.
- [SECURITY_MODEL.md](SECURITY_MODEL.md): safety controls and auth model.
- [CLIENT-CONTRACT.md](CLIENT-CONTRACT.md): exact MCP request and tool argument
  contract.
- [AGENT_ROUTING.md](AGENT_ROUTING.md): agent-facing routing between this
  operator MCP, Cloudflare managed MCP servers, and Cloudflare-documented CLIs.
- [API-PARITY.md](API-PARITY.md): generic Cloudflare REST API parity model.
- [../packaging/codex/cloudflare-managed-mcp.example.toml](../packaging/codex/cloudflare-managed-mcp.example.toml):
  Codex profile template for placing this guarded server beside Cloudflare's
  official managed MCP endpoints.

## Preconditions

Before using the server for production-like changes:

- Configure a Cloudflare API credential source:
  - `CLOUDFLARE_MCP_API_TOKEN`, or
  - `CLOUDFLARE_MCP_API_TOKEN_SOURCE=header|header_or_config`.
- Configure account and zone defaults or pass IDs per call:
  - `CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID`
  - `CLOUDFLARE_MCP_DEFAULT_ZONE_ID`
- Enable MCP auth before any non-loopback bind. Set both
  `CLOUDFLARE_MCP_AUTH_RESOURCE_URL` and `CLOUDFLARE_MCP_AUTH_AUDIENCE` to
  explicit HTTPS URLs; non-loopback binds do not derive or accept HTTP values.
- Use least-privilege Cloudflare API tokens.
- Keep secrets in environment variables or protected files outside the
  repository.

Recommended preflight checks:

```bash
cargo test tools::tests::tool_schema_snapshot_contract_is_stable
cargo test --test mcp_stdio_smoke
CLOUDFLARE_MCP_AUTH_MODE=off cargo run -- --print-tools
```

For release binaries, verify the promoted binary rather than only the source
tree:

```bash
CLOUDFLARE_MCP_AUTH_MODE=off cargo build --release
CLOUDFLARE_MCP_AUTH_MODE=off target/release/cloudflare-mcp --print-tools
scripts/generate-release-provenance.sh \
  --binary target/release/cloudflare-mcp \
  --output .tmp/release-provenance.json
jq . .tmp/release-provenance.json
```

If an existing `cloudflare-mcp --stdio` process is already serving traffic,
verify that process as well as the file on disk. Stdio sessions keep the old
executable inode until restarted, so a promoted symlink or copied binary is not
proof that the live process has changed:

```bash
pgrep -af 'cloudflare-mcp.*--stdio'
readlink -f /proc/<pid>/exe
sha256sum /proc/<pid>/exe target/release/cloudflare-mcp
```

The provenance manifest is secret-free. It records the source commit, dirty
state, binary SHA-256 and size, registered tool count, normalized tool inventory
hash, committed schema/catalog hashes, and pinned `mcp-toolkit-rs` revision.
Treat it as the release note for an installed binary. For a promoted symlink or
versioned install directory, keep the manifest beside the binary or in the
release artifact bundle so agents can compare:

- source commit versus repository `main` or the release tag,
- binary SHA-256 versus the installed file,
- tool count and inventory hash versus `--print-tools`,
- schema snapshot hash versus `spec/tool_schema_snapshot.v1.json`,
- `/proc/<pid>/exe` hash for any already-running stdio process.

## Exact-byte D1 migration manifests

Use `d1_apply_migration_manifest` for an approval-gated D1 migration family.
First run it with `dry_run=true`; retain the returned `plan_sha256`, which is
bound to the exact SQL bytes and current Wrangler ledger prefix. A live call
must submit that value as `approved_plan_sha256` and configure
`CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT` to a pre-created, operator-owned,
non-group/world-writable directory shared by every MCP process that can target
the database. On Linux the root must be an absolute real directory owned by the
current operator with mode `0700` (or stricter), and every non-sticky ancestor
must be non-writable. The MCP permanently creates one private target directory
per account/database. It retains held root, target, guard and active file
descriptors while an apply is in progress. The target contains a permanent
`guard.lock`, acquired with a cross-process file lock, and terminal evidence such as
`retired.<nonce>.lease.json`; neither is cleanup material. While holding that
guard, the MCP writes `active.lease.json` with mode `0600` and synchronizes the
directory. Every active, abort and retirement namespace transition is relative
to the held target directory descriptor; replacing the target pathname cannot
redirect it into a replacement directory. It revalidates root, ancestors,
directory, guard, identity and mode before every provider boundary. Do not use
a shared writable directory or manually rename or remove any lease evidence by
pathname.

The exact-byte manifest boundary accepts at most 16 MiB of aggregate SQL and
moves the supplied manifest into validation without cloning its SQL strings.
Split a larger migration family before review rather than increasing this
operator-surface memory bound.

A later invocation stops before provider I/O when it sees an active or
`retiring.lease.json` entry, including one that is malformed, a symlink or
non-regular. It must be resolved only through the governed recovery path,
never inferred stale or reclaimed. Normal terminal completion moves
the active file under the held guard to `retiring.lease.json`, synchronizes the
target directory, then records `retired.<nonce>.lease.json` without replacement
and synchronizes again. A failed synchronization restores the exact active
entry or leaves active/retiring evidence as an explicit blocker. A failed
creation is retained as
`aborted-create.<nonce>.lease.json`; production code never unlinks a lease file
or directory. The manifest tool never reopens a migration directory after
review and never retries an ambiguous provider write. An unknown outcome retains
the active target lease: reconcile provider ledger evidence and the reported
lease identity before any governed recovery. A matching ledger filename is only
an observation: it does not attest to the reviewed SQL bytes or complete
provider transaction, and therefore never authorizes lease release after an
ambiguous apply. This guarantee is limited to a trusted Linux filesystem that
supports working `renameat2(RENAME_NOREPLACE)`, directory `fsync`, and advisory
file locks. It is a shared-filesystem lease, not a Cloudflare-distributed lock;
cross-host or other shared-filesystem semantics require separate proof.
Separate provider/distributed coordination remains required when MCP instances
do not share that root. The product-neutral governed recovery path remains
required for retained, malformed, or tampered evidence. Non-Linux installations or
unsupported filesystems fail closed before provider I/O.

### Read-only retained-manifest reconciliation

When an ambiguous apply retains `active.lease.json` or a failed terminal move
leaves `retiring.lease.json`, use `d1_reconcile_migration_manifest`; do not run
the apply tool again. Supply the same complete exact-byte manifest and the
reported approved-plan, nonce, and payload digests. Also supply ordered,
bounded `state_expectations` for every manifest prefix from zero through the
full manifest; a selected or partial prefix set is not accepted. Each state
names the exact `sqlite_master` object type/name/table and SQL digest, complete
`table_xinfo` rows, and complete foreign-key definitions for every declared
table. The tool independently derives every CREATE target at every prefix and
requires exact agreement, so a caller cannot omit a created table or index and
obtain convergence; the extended assertion applies the same rule to views and
triggers.

Select one explicit built-in effect assertion:

- `effect_assertion_id=schema_create_only_v1` remains the backward-compatible
  table/index contract and still rejects views and triggers.
- `effect_assertion_id=schema_create_tables_indexes_views_triggers_v1` adds
  versioned `CREATE VIEW` and `CREATE TRIGGER` classification. Each prefix must
  name every view as `type=view`, `name=<view>`, `table_name=<view>` and every
  trigger as `type=trigger`, `name=<trigger>`, `table_name=<parent table>`, with
  the exact `sqlite_master.sql` SHA-256. The trigger parent table must exist in
  that selected prefix. Only physical tables receive `table_xinfo`,
  `foreign_key_list`, and `foreign_key_check` expectations; views and triggers
  remain covered by the complete exact `sqlite_master` union.
- `effect_assertion_id=schema_create_objects_additive_v1` preserves that full
  CREATE-object proof and additionally classifies at most one canonical
  unqualified `ALTER TABLE <parent> ADD [COLUMN] <column> <type>` per manifest
  entry. The bounded column definition may add `NOT NULL`, one literal
  `DEFAULT` (`NULL`, signed integer, or quoted string), and one trailing
  `CHECK`, in that order when present. CHECK expressions are capped by token
  count, nesting depth, literal size, and IN-list length; they may reference only
  the added column through `IS NULL`, literal equality, a literal `IN` list, and
  the pure `length(column)` or
  `substr(column, positive_integer, positive_integer)` forms joined by
  `AND`/`OR`. Subqueries, other-column reads, unknown functions/operators,
  `REFERENCES`, `UNIQUE`, `PRIMARY KEY`, `COLLATE`, `GENERATED`, compound types,
  quoted/schema-qualified identities, and every other ALTER form are rejected.
  The parent must be present in the baseline or a strictly earlier prefix.
  Every transition must preserve the complete ordered prior
  `table_xinfo` and foreign-key state, append exactly one matching column, and
  bind the changed parent to a distinct reviewed `sqlite_master.sql` digest.
  The assertion also accepts exactly `PRAGMA foreign_keys = ON` as semantic
  migration intent. It does not execute caller SQL or claim that the provider
  connection retained PRAGMA state; proof remains the fixed read-only schema
  and foreign-key snapshot.
- `effect_assertion_id=schema_create_objects_additive_seed_rows_v1` extends the
  additive assertion with one canonical top-level seed INSERT per
  manifest-created target. Require plain unqualified table/column identifiers,
  explicit columns, bounded literal `VALUES` tuples, CREATE-before-seed, and
  seed-before-trigger ordering across the complete manifest. Reject every
  classified `CREATE ... IF NOT EXISTS`; seed authority requires an actual
  unconditional creation. Add the exact
  cumulative `seed_tables` summary to every prefix expectation: target, ordered
  columns, row count, and local row-set SHA-256. Treat ASCII case variants as
  one SQLite CREATE, ALTER, index, trigger, and seed target while retaining the
  reviewed `CREATE TABLE` spelling in expectations and fixed queries. Use the
  deterministic first-encountered manifest parent spelling for baseline tables
  not created by this manifest when ALTER/index/trigger parents vary only by
  SQLite ASCII case. Keep provider and expectation spelling unchanged in the
  selected fixed proof. Permit only identity-stable affinity pairs: for
  non-STRICT tables, TEXT literals on
  TEXT/BLOB columns and INTEGER literals on INTEGER/NUMERIC/BLOB columns; for
  STRICT tables, TEXT literals on exact TEXT columns and INTEGER literals on
  exact INT/INTEGER columns. Reject STRICT BLOB seeds before custody/provider
  access. This assertion performs one
  primary-current prefix-selection read followed by two identical complete
  primary-current reads. Each complete read covers the bounded full-manifest
  `sqlite_master` object union and safe table-valued PRAGMAs for the bounded
  full-manifest physical-table union; every prefix therefore proves future
  objects and future table structure absent as well as current facts present.
  Match schema-object membership under SQLite ASCII `NOCASE`, retain exact
  observed spelling and canonical type/name ordering, and reject aliases or
  conflicting spellings.
  Seed-row SELECTs remain selected-prefix and existence-aware. The full-manifest
  seed registry must prove three distinct prefix states: no seed-row SELECT from
  a table before CREATE, an exact zero-row table projection after CREATE and
  before INSERT without depending on columns added by a later prefix, and the
  exact typed row set at or after INSERT. Any row in the zero-row window must
  fail on the first complete proof with two total provider reads and zero
  mutations.
  Terminal dry run and live finalization must rederive and repeat that same
  selected-prefix proof. Require each complete proof ledger to equal the exact
  initial selected ledger, then separately require the two complete snapshots
  to be canonically equal. An equal pair at a different prefix is a
  reconciliation contradiction, not authority to reselect. Record only the
  aggregate-safe `selection_binding` query/ledger digests and selected prefix;
  do not copy raw provider rows. Parse every provider response locally, then
  freshly revalidate retained lease custody before reporting either the parsed
  snapshot or a parse failure as verified custody. Otherwise verify three
  provider reads, zero provider mutations, exact aggregate seed summaries, and
  no raw seed values in the response. Any ambiguity or mismatch remains
  reconciliation-required.
  The predecessor assertions do not accept top-level INSERT.

The successful response identifies that same closed scope without flattening
the broader assertions back to the legacy label: `effect_assertion.scope`
reports `schema_create_only`, `schema_create_tables_indexes_views_triggers`, or
`schema_create_objects_additive`, or
`schema_create_objects_additive_seed_rows` respectively, alongside the complete
allowed `schema_object_types` array.

For every assertion, the configured `migrations_table` is a reserved schema
identifier under SQLite ASCII case-insensitive matching. A manifest must not
create an object with that name, create an index or trigger on that table, or
use additive ALTER against it. Every accepted trigger contributes bounded
lexical evidence from the complete post-parent header (including `WHEN`) and
body: each word, quoted identifier, and string-literal value is retained, while
symbols carry no value. Any exact ASCII-case-insensitive collision fails
closed, including a string literal; longer unrelated token values remain valid.
This is rejected before expectation validation, custody
inspection, or provider access so an injected ledger INSERT cannot activate
manifest-defined behavior.

The successful response names the selected assertion and its exact object-type
scope. That ID is also part of the reconciliation-plan digest, terminal-plan
digest, version-2 durable receipt, and exact replay. Never change it between
approval and finalization, even when both assertions derive identical state for
a table/index-only manifest.

Receipt reads are deliberately dual-version while writes are version 2 only.
An exact canonical predecessor version-1 receipt has its original field set and
is mapped exclusively to `schema_create_only_v1`; it can resume active or
retiring custody and replay a completed retirement. It never attests the
extended assertion. Unknown fields, duplicate keys, malformed/noncanonical
bytes, or an attempt to pair version 1 with the extended assertion fail closed
before provider access.

Completed-retirement replay is not receipt-only lookup. Before returning the
zero-provider success, the terminal boundary reclassifies the supplied manifest,
validates the complete typed expectations, and locally recomputes the applicable
historical version-1 or current version-2 reconciliation-plan digest. Changed
manifest names or bytes, expectation objects/tables, prefixes, or assertion
scope therefore cannot borrow an incumbent receipt.

The extended classifier keeps an entire trigger body together across internal
semicolons and nested `CASE ... END`, then accepts only bounded canonical
trigger identities, a supported event/header, and semicolon-terminated
`INSERT`, `UPDATE`, `DELETE`, or `SELECT` body statements. It rejects malformed
or unclosed quotes/comments/bodies, `TEMP`/`TEMPORARY`, schema-qualified names,
reused identities, and top-level DML. The two CREATE-only assertions refuse
arbitrary DML, ALTER, DROP, PRAGMA, virtual tables, `CREATE TABLE AS SELECT`,
`CREATE TABLE AS VALUES`, and other data-producing or unclassified CREATE
effects. The additive assertion refuses those same effects except for its exact
ADD COLUMN and foreign-keys-on forms; a caller assertion is not proof. An
effect capability gap means retain the lease and add
a purpose-built registry assertion/readback contract before continuing.

The tool opens the existing target and guard without creating entries, requires
exactly one active or retiring regular private evidence file, and holds the
guard across two complete internally generated read-only batches. It returns
`not_committed`, `partial_state_converged`, or `full_state_converged` only when
the current ledger is an exact manifest prefix, the retained approved plan
reconstructs uniquely from that prefix relationship, both canonical snapshots
match, and schema/FK proof is complete. These labels are documented atomic-state
inference, not proof of which provider attempt caused the state.

Every fixed result set carries a query-bound statement marker and a mandatory
sentinel row, including result sets with no data rows. Parsing requires the
exact marker, exact row shape, explicit success, empty errors, and—when
present—boolean `changed_db=false` plus integer `changes=0` and
`rows_written=0`. Every fixed result set in both batches must also carry exact
`meta.served_by_primary=true`; missing metadata or a false, null, non-boolean,
or mixed primary marker fails closed as contradictory evidence. Response bodies
are capped at 16 MiB from the HTTP stream; the adapter stops before buffering a
body beyond that bound.

Before any successful-status reconciliation response object is converted to
`serde_json::Value`, the bounded raw body is decoded through a reconciliation-
local recursive visitor that rejects duplicate keys in the outer envelope and
every nested object, including result, metadata, error, and row objects. Either
key order fails as contradictory evidence. The exact raw-body digest, byte
count, HTTP status, and completed-read lifecycle are captured first; no key or
value from the rejected body is returned. This stricter decoder is deliberately
limited to reconciliation reads and does not change generic Cloudflare response
paths or the migration-write decoder.

The reconciliation HTTP client does not follow redirects. Interpret
`provider_read_lifecycle` in order: `pre_dispatch` means no provider call;
`attempted` with `not_received` means transport outcome without a response;
`received` plus `not_read`, `partially_read`, or `completely_read` records the
body boundary and exact captured HTTP status. A response-stream failure is
`not_read` when zero body bytes were accumulated and `partially_read` only
after at least one byte was accumulated. Preserve the status for invalid
UTF-8, malformed JSON, truncated streams, and oversized bodies. Treat 401,
403, 429, and every 5xx as unavailable and never retry the same attempt.

Interpret custody fields literally. Validation failures before custody lookup
return `lease_retained=null` and `custody_status=not_inspected`. Inspection
failures return `lease_retained=null` and `custody_status=inspection_failed`.
Both are before provider-adapter invocation and must explicitly return
`provider_calls=0` with `provider_read_lifecycle=[]`; missing fields are not
zero-call evidence. Adapter-local token/config failure is different: it records
one `pre_dispatch` lifecycle entry even though its provider-call count is zero.
Public semantic validation is ordered target, migrations table, manifest, then
migration family. Any failure there returns the complete fail-closed
reconciliation envelope with contradictory capability, uninspected custody,
null query digest, empty response/lifecycle evidence, and zero provider or
local mutations; it does not acquire lease custody or contact D1. JSON-RPC and
generated-schema parse failures remain MCP deserialization errors without a
structured reconciliation envelope because semantic tool execution has not
begun.
An omitted `account_id` with no configured default is part of target semantic
validation and must return that same zero-call envelope before any lease or D1
access.
Only a successfully acquired and revalidated retained lease may report
`lease_retained=true` and `custody_status=retained_evidence_verified`. If that
evidence drifts, conflicts, or fails revalidation around a provider read, the
result returns `lease_retained=null` and
`custody_status=retained_evidence_unverified`; do not infer that the named
evidence was removed. HTTP 429 and 5xx responses make provider evidence
unavailable and never authorize an automatic retry, including when the body
exceeds the streaming byte bound. Contradictory ledger, schema, plan, or
two-read evidence discovered after successful custody revalidation reports the
retained evidence as verified and includes the exact two provider calls; only
custody drift changes that status to unverified. `response_evidence` records
only captured response bodies; `provider_read_lifecycle` independently records
every invocation. Invocation position and count, not response-value equality,
determine that chronology: two byte-identical successful reads remain two
evidence and lifecycle entries, while reprocessing an already merged product
is idempotent. After one complete read, a second transport failure or
pre-dispatch adapter failure therefore leaves one response summary but two
chronological lifecycle entries. `provider_calls` counts only actual provider
attempts: it is `1` when that second invocation fails before dispatch and `2`
when the second invocation reaches transport. Standalone pre-dispatch failure
remains zero provider calls.
Revalidation runs after every
attempted provider call even when the provider returns an error. If provider
failure and custody drift coincide, retain the provider classification and
chronological response evidence while treating custody as unverified; the
`custody_cause` names the separate revalidation failure.

All read-only reconciliation results retain the lease and prohibit retry of the
same migration attempt. Record the query SHA-256, both bounded response-body
digests, expectation proof, canonical snapshot SHA-256, scope-completeness
fields, outcome/prefixes, and `reconciliation_plan_sha256`. Do not manually
rename or remove custody evidence.

### Terminal retained-manifest reconciliation

Use `d1_finalize_migration_reconciliation` only after the read-only result is
recorded. Supply every original manifest/expectation input plus the exact
reconciliation-plan, expectation-proof, query, snapshot, outcome and prefix
values, and preallocate distinct opaque request and attempt identities as
lowercase SHA-256 digests. First call with `dry_run=true`; it re-runs two
complete primary-current batches and returns `terminal_plan_sha256`. Record and
independently approve that exact digest before a live call. A digest derived
after the live read is not approval.

Before any custody inspection, confirm that original and current prefixes are
both bounded by the exact supplied manifest and apply this closed outcome
matrix:

- `not_committed`: current equals original;
- `partial_state_converged`: original is less than current and current is less
  than the manifest length;
- `full_state_converged`: original is less than current and current equals the
  manifest length.

No other outcome/prefix product may be planned, persisted, or replayed.
Canonical v1/v2 receipt readback cannot rederive manifest length, so it first
enforces the strongest independent subset: equal prefixes only for
`not_committed`, and strict growth for both converged outcomes. The terminal
request then rebinds that receipt to the supplied manifest and enforces the
complete matrix above. Canonical-but-contradictory restored evidence fails
before provider access or local namespace mutation in active, retiring, and
retired custody.

Reuse the exact same effect assertion in reconciliation, terminal dry run, and
live finalization. The terminal path derives and verifies the same complete
table/index/view/trigger inventory; it does not downgrade the assertion or
replace view/trigger `sqlite_master` proof with table PRAGMAs.

The live call requires `approved_terminal_plan_sha256` and follows this fixed
order while holding the permanent target guard:

1. Re-run the two-batch retained-manifest proof and require exact agreement
   with every approved evidence digest and outcome/prefix.
2. Perform one fresh primary-current batch and custody revalidation immediately
   before receipt persistence.
3. Create `terminal-reconciliation.<nonce>.receipt.json` without replacement,
   synchronize it and the target directory, and read it back through the held
   descriptor. An exact incumbent is replay; any changed or malformed incumbent
   conflicts.
4. Perform another fresh primary-current batch and custody/receipt revalidation
   immediately before retirement.
5. Move exact retained evidence through active -> retiring ->
   `retired.<nonce>.lease.json` with no-replace and directory synchronization at
   each boundary.

The terminal tool never sends D1 SQL writes and never retries an unavailable or
ambiguous provider read. Interpret its custody product literally. Only a fresh
revalidation of physical `active.lease.json` may return
`lease_retained=true`, `custody_status=retained_evidence_verified`, and
`lease_decision=retain`. Pre-inspection rejection returns null plus
`not_inspected`; inspection failure returns null plus `inspection_failed`;
retiring evidence returns null plus `retiring_evidence_verified`; and drift or
otherwise unverified custody returns null plus
`retained_evidence_unverified`. Those null states omit `lease_decision`; they
do not fabricate retention or retirement authority. Verified physical
retirement returns `lease_retained=false`,
`custody_status=retired_evidence_verified`, and `lease_decision=retired`, even
when the missing or invalid receipt then fails the request closed.

Failure before the receipt keeps the retained lease only when the response also
proves that active custody state.
Failure after the receipt leaves that durable receipt plus retained or retiring
evidence for exact replay. A terminal retirement with no exact receipt is an
order violation and cannot be repaired by creating a receipt afterward. Exact
replay after completed retirement validates the receipt and retired lease and
reproduces the receipt-bound expectation proof and versioned reconciliation
plan from the supplied manifest, including the complete outcome/prefix matrix,
before returning with zero provider calls.
If another exact caller completes retirement after initial inspection but
before reconciliation preparation, a preparation failure with exactly zero
provider calls permits one fresh custody inspection. It converges only through
the same exact completed-retirement replay validation. Once any provider call
has been attempted, the failure is not eligible for this convergence path and
remains reconciliation-required. Once a refresh or read reports unverified
custody, preserve that negative classification through terminal error handling;
a later physical inspection that appears restored cannot overwrite it.
Null, array, primitive, malformed,
duplicate-keyed, unknown-keyed, noncanonical, contradictory, hard-linked, or
conflicting namespace evidence fails closed. Never delete, rewrite, rename, or
copy these products manually.

For CI-built release bundles, the `Rust Validation` workflow uploads a
downloadable artifact named `cloudflare-mcp-linux-x86_64-stdio-<git-sha>` that
contains:

- `target/release/cloudflare-mcp`
- `.tmp/release-provenance.json`

This is the preferred install source when the operator wants the local machine
to run exactly the binary GitHub Actions validated. Example retrieval:

```bash
gh run download <run-id> \
  --repo sednalabs/cloudflare-mcp \
  --name cloudflare-mcp-linux-x86_64-stdio-<git-sha> \
  --dir /tmp/cloudflare-mcp-release-<git-sha>
```

After download, compare the installed file and the artifact manifest before
promoting a new `current` symlink or replacing the current binary in a versioned
install directory.

## Safety Profiles

### Read-Only

Use read-only mode when no mutation should be possible:

```bash
export CLOUDFLARE_MCP_READ_ONLY=1
```

Expected behavior:

- `tools/list` includes only read-only tools.
- Mutating tools are denied.
- `health` reports `read_only_mode=true`.

### Curated Tools Only

Use curated-tools-only mode when broad generic REST execution should be hidden:

```bash
export CLOUDFLARE_MCP_API_PARITY_ENABLED=0
```

Expected behavior:

- Generic `api_*` parity tools are hidden and denied.
- Curated Cloudflare workflow tools remain governed by normal auth and
  read-only policy.

### Approval-Gated Apply

Use elicitation when dangerous apply calls require human approval:

```bash
export CLOUDFLARE_MCP_ELICITATION_ENABLED=1
export CLOUDFLARE_MCP_ELICITATION_APPLY_ONLY=1
```

Expected behavior:

- Configured dangerous tools prompt before apply.
- Dry-run calls bypass approval by default.
- Clients without elicitation capability fail closed unless explicitly
  configured otherwise.
- Approval prompts include a request digest that must be echoed in the response.

## Baseline Read-Only Audit

Before the baseline audit, a hosted deployment may enroll its Cloudflare grant
without copying an API token to the host:

1. Register a private Cloudflare OAuth client for the owning account with
   `authorization_code` and `refresh_token` grants, the exact HTTPS callback
   `https://<host>/oauth/cloudflare/callback`, and reviewed dot-delimited scopes.
2. Put the client secret in an owner-only secret file and configure the
   `CLOUDFLARE_MCP_UPSTREAM_OAUTH_*` environment values documented in the
   README. Leave the refresh-token cache outside the source checkout.
3. Start the service and call `cloudflare_auth_status`. It must report OAuth
   enabled, a configured client and callback, and no grant on first use.
4. Call `cloudflare_auth_login`, open its short-lived authorization URL, and
   complete Cloudflare consent. For stdio on a remote desktop host, register a
   fixed `http://127.0.0.1:<port>/oauth/cloudflare/callback` URI so the MCP
   process can own the loopback listener. Do not paste or log the callback URL.
   Poll status until `last_login_status=succeeded`.
5. Call `cloudflare_auth_probe`. Continue only when it reports
   `credential_verified=true`.

If enrollment fails, start a fresh login rather than replaying an old callback.
To remove local custody, call `cloudflare_auth_logout` first without and then
with `confirm=true`; revoke the application separately in Cloudflare when full
revocation is required.

When the task needs broad or current Cloudflare discovery before a guarded
operator action, add the relevant managed MCP endpoints from
`packaging/codex/cloudflare-managed-mcp.example.toml` to the agent profile.
Use OAuth for interactive sessions or an out-of-repository bearer token for
automation. Treat a configured managed endpoint as connection setup only:
account/API endpoints still need Cloudflare authorization before read-only
calls work.

Before relying on a managed endpoint, run a safe smoke check:

```bash
curl -sS -X POST https://docs.mcp.cloudflare.com/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cloudflare-mcp-smoke","version":"0.0.0"}}}'
```

For account/API endpoints such as `https://mcp.cloudflare.com/mcp` or
`https://graphql.mcp.cloudflare.com/mcp`, an unauthenticated `401 invalid_token`
is an acceptable pre-auth smoke result. The next proof must be an authorized
read-only MCP call through the target client or an allowlisted probe profile.

For this self-hosted server in Streamable HTTP mode, distinguish MCP auth
readiness from Cloudflare API capability readiness:

```text
mcp_probe probe_http_smoke url=http://127.0.0.1:9501/mcp expect_auth_required=true
mcp_probe probe_handshake transport=streamable-http url=http://127.0.0.1:9501/mcp expect_auth_required=true
```

Those checks prove the HTTP/OAuth metadata and unauthenticated challenge shape.
They do not prove a logged-in MCP client. The first authenticated pre-mutation
tool call should be:

```text
tools/call name=capabilities_check arguments='{"account_id":"<account_id>","zone_id":"<zone_id>","expected_zone_name":"<zone_name>","require_explicit_zone_id":true}'
```

Treat `preflight.ok=false` as a stop condition until every entry in
`preflight.findings` is understood. In particular, `target.zone_id_from_default`
means the workflow is relying on `CLOUDFLARE_MCP_DEFAULT_ZONE_ID`; pass the
intended zone explicitly for DNS, Pages, Access, Worker, and publish work.

Capture current state before mutation:

```text
tools/call name=list_tunnels arguments='{"account_id":"<account_id>"}'
tools/call name=list_dns_records arguments='{"zone_id":"<zone_id>","hostname":"<hostname>"}'
tools/call name=list_access_apps arguments='{"account_id":"<account_id>","hostname":"<hostname>"}'
tools/call name=publish_preflight arguments='{"account_id":"<account_id>","hostname":"<hostname>"}'
```

Record:

- Selected tunnel identity.
- Existing DNS route state.
- Existing Access app and policy state.
- Publish preflight decision code and reason.

## Dry-Run Planning

Run mutating tools with `dry_run=true` first. Include `x-correlation-id` on
mutating requests so dry-run, apply, and rollback evidence can be linked.

Examples:

```text
tools/call name=ensure_tunnel arguments='{
  "account_id":"<account_id>",
  "tunnel_name":"<tunnel_name>",
  "dry_run":true
}'

tools/call name=upsert_access_app arguments='{
  "account_id":"<account_id>",
  "hostname":"<hostname>",
  "app_name":"<app_name>",
  "dry_run":true
}'

tools/call name=lock_first_publish arguments='{
  "account_id":"<account_id>",
  "zone_id":"<zone_id>",
  "hostname":"<hostname>",
  "target":"<target>",
  "dry_run":true
}'

tools/call name=workers_upload_script arguments='{
  "account_id":"<account_id>",
  "script_name":"<worker_script>",
  "main_module":"index.js",
  "script_path":"dist/worker/index.js",
  "metadata":{"compatibility_date":"YYYY-MM-DD"},
  "dry_run":true
}'
```

Review the plan and policy output before apply. For `workers_upload_script`,
review `upload.sha256`, `upload.metadata_sha256`, and `upload.metadata_keys`;
the tool intentionally reports digests and keys instead of raw Worker metadata
values. Apply by echoing `required_confirmation_token` in
`confirmation_token`. Treat `workers.upload_readback_mismatch` as a failed
deployment proof even when Cloudflare accepted the upload request, because the
settings readback did not match the requested module.

When a create-only module upload returns `main_module:null` in settings, that
field is not treated as creation proof. The tool binds the upload response etag
to one exact listing entry and one version detail's `resources.script.etag`,
handlers, and a structurally valid named-handler array (which may be empty).
Any handler names and export members must be unique, nonblank, and byte-exact;
leading or trailing whitespace fails closed. The default
and named handler arrays may each be empty, but at least one valid entrypoint
must exist overall. Version lists must carry exhaustive authoritative
pagination metadata and are reread after the detail; missing, truncated,
duplicate, malformed, ambiguous, or conflicting records stop the operation.
The response contains only a sanitized attestation, never raw version metadata.

For a first-install-only deployment, add `"create_only":true` to both the
dry-run and apply calls. The confirmation token binds this flag, and apply sends
Cloudflare's atomic `If-None-Match: *` precondition. A pre-existing script must
end with `workers.upload_create_only_conflict`; do not retry or fall back to an
unconditional upload. Timeout, transport, response-read/decoding, retryable 5xx,
and success envelopes with a missing or null result end with
`workers.upload_create_only_outcome_uncertain` and `retryable:false`; read back
the Worker and reconcile provider evidence before deciding whether to continue
or claim creation.

For projects that already use Wrangler to build a multipart Worker bundle, pass
`multipart_path` instead of `script_path`/`script_content`/`main_module`.
The MCP infers `content_type` from a leading multipart boundary when possible;
otherwise pass `content_type:"multipart/form-data; boundary=<boundary>"`.
Multipart uploads still require dry-run review and the confirmation token, but
`readback_verification` reports module-name verification as not applicable
because the bundle owns its module graph.

## Apply Sequence

For exposure workflows, use this order:

1. Ensure or identify the tunnel.
2. Generate and review ingress configuration.
3. Ensure Access app and policies.
4. Run `publish_preflight`.
5. Run `lock_first_publish` with `dry_run=true`.
6. Apply `lock_first_publish` only after the plan is accepted.
7. Verify DNS with `verify_dns_route`.
8. Verify HTTP state with `verify_http_gate`.

Do not bypass publish preflight unless the policy explicitly permits override
and the operator records a reason.

## Generic API Parity Workflow

Prefer curated tools when available. For operations without a curated tool:

```text
tools/call name=api_find_operations arguments='{"query":"<product or endpoint>"}'
tools/call name=api_get_operation arguments='{"operation_id":"<operation-id>"}'
tools/call name=api_prepare_call arguments='{"operation_id":"<operation-id>","path_params":{},"query_params":{}}'
tools/call name=api_read arguments='{"operation_id":"<get-operation-id>","path_params":{},"query":{}}'
tools/call name=api_mutate arguments='{"operation_id":"<mutating-operation-id>","path_params":{},"body":{},"dry_run":true}'
```

`api_mutate` apply calls require the dry-run confirmation token. Denied
high-risk categories fail closed.

### Bot Management permission preflight and 403 recovery

The zone Bot Management update operation requires the complete permission pair
`Bot Management Write` and `Zone Settings Write`. Do not infer readiness from
one member of the pair or from a successful token-verification status alone.

Before requesting a mutation confirmation token:

1. Read the account-owned token with `account_api_tokens action=get`.
2. Pass the fresh permission-group names as `api_mutate.token_permissions` on
   the Bot Management update dry-run.
3. If the response names missing permissions, run its
   `account_api_token_permission_plan` call, review the preserved-policy delta,
   then run the returned `account_api_tokens` update as dry-run followed by one
   exact confirmation-gated apply.
4. Read the token back and confirm both permission names are present.
5. Rerun the original Bot Management mutation dry-run, apply it once with that
   new confirmation token, then use
   `bot-management-for-a-zone-get-config` through `api_read` for authoritative
   configuration readback.

A first HTTP 403, including Cloudflare error 10000, is a recoverable
permission/preflight signal, not proof that interactive authentication is
required, and is not a goal-blocking condition. Do not switch to a dashboard,
remote desktop/noVNC, or human authentication after that first response.
Escalate to a person only when account-token inspection or the guarded update
path is positively unavailable through the MCP, or when exact provider evidence
proves a distinct external authority requirement. Record the specific
unavailable tool or provider authority; do not report a generic auth blocker.

For billing or D1 usage-spike investigations:

```text
tools/call name=account_billing_usage arguments='{"mode":"paygo","from":"<iso-start>","to":"<iso-end>"}'
tools/call name=graphql_analytics_query arguments='{"query":"query D1Usage($accountTag: string!) { viewer { accounts(filter: { accountTag: $accountTag }) { d1AnalyticsAdaptiveGroups(limit: 10000) { sum { rowsRead rowsWritten readQueries writeQueries } dimensions { date databaseId } } } } }","variables":{"accountTag":"<account-id>"}}'
```

Use billing usage for billable records and GraphQL analytics for attribution.
The REST executor derives path parameters from URL templates, so operations with
stale catalog parameter metadata should not send literal `{account_id}` paths.

For WAF rule and Security Events investigations:

```text
tools/call name=waf_ruleset_summary arguments='{"scope":"zone","phases":["custom","managed","ratelimit"],"include_rules":true}'
tools/call name=waf_security_events_summary arguments='{"window_hours":24,"group_by":["action","source","host","path","rule"],"sample_limit":10}'
tools/call name=waf_rule_activity arguments='{"rule_id":"<rule-id>","window_hours":24,"phases":["custom","managed","ratelimit"]}'
```

WAF Rulesets are read through the Ruleset Engine entrypoint phases
`http_request_firewall_custom`, `http_request_firewall_managed`, and
`http_ratelimit`. Security Events analytics use Cloudflare Analytics GraphQL
dataset `firewallEventsAdaptive`; a single HTTP request can produce multiple
security events and large windows may be sampled.

## R2 Object Workflow

Inspect before reading or writing:

```text
tools/call name=r2_inspect_object arguments='{"bucket_name":"<bucket>","object_key":"<key>"}'
```

The R2 helpers use S3-compatible credentials, not the general Cloudflare API
token. A `403 Forbidden` on an existing object usually means the configured R2
token does not include that bucket. Treat the configured R2 access-key id as
the account-owned token id and inspect it without exposing the secret:

```text
tools/call name=account_api_tokens arguments='{
  "action":"get",
  "token_id":"<configured-r2-access-key-id>"
}'
```

If the bucket is absent from `policies[].resources`, preserve every existing
resource and the `Workers R2 Storage Bucket Item Read` permission, add only the
missing bucket resource, then use `account_api_tokens action=update` with the
normal dry-run and confirmation-token flow. Updating that policy retains the
existing S3 key material, so no secret rotation or MCP restart is required.
Re-run both `r2_inspect_object` and a bounded `r2_get_object` byte-range after
the change. Do not broaden the token to write access merely to solve a read
failure.

For large or binary objects, use file response mode:

```text
tools/call name=r2_get_object arguments='{
  "bucket_name":"<bucket>",
  "object_key":"<key>",
  "response_mode":"file",
  "output_path":"/path/to/output/object.bin",
  "create_parent_dirs":true
}'
```

For writes, run dry-run first:

```text
tools/call name=r2_put_object arguments='{
  "bucket_name":"<bucket>",
  "object_key":"<key>",
  "content_text":"<content>",
  "dry_run":true
}'
```

## External Service Bridge Workflow

The optional external service bridge is for deployments that need to call
approved operator endpoints with server-held credentials.

Before enabling it:

- Configure only HTTPS allowlist prefixes that the server should call.
- Store credentials outside the repository.
- Use dry-run before live requests.
- Review sanitized response output and audit metadata.

Example dry-run:

```text
tools/call name=portal_agent_request arguments='{
  "url":"https://ops.example.com/api/agent/task",
  "method":"POST",
  "body":{"title":"Example task","content":"..."},
  "use_agent_token":true,
  "use_access_service_token":false,
  "dry_run":true
}'
```

## Rollback and Containment

For accidental exposure or failed verification:

1. Run `emergency_unpublish` with `dry_run=true`.
2. Apply `emergency_unpublish` after reviewing the plan.
3. Re-run `verify_dns_route`.
4. Re-run `verify_http_gate`.
5. Inspect Access app and policy state.
6. Record the correlation ID and final verification state.

`emergency_unpublish` is idempotent across repeated invocations.

## Validation For Changes

For docs-only changes, scan public wording and verify links.

GitHub Actions also runs CodeQL as a static-analysis guardrail. SARIF upload is
disabled in this repository's CodeQL workflow, so the guardrail can run even
when GitHub code scanning is not enabled for the repository.

For tool, transport, auth, or runtime behavior changes:

```bash
cargo fmt --check
cargo test
cargo test --test mcp_stdio_smoke
CLOUDFLARE_MCP_AUTH_MODE=off cargo run -- --print-tools
```

For tool schema changes:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test tools::tests::tool_schema_snapshot_contract_is_stable
cargo test tools::tests::tool_schema_snapshot_contract_is_stable
```

CodeQL and static checks are useful guardrails, but MCP stdio/runtime tests are
the source of truth for tool callability.
