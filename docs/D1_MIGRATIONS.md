# D1 migration and recovery guide

This guide explains how the curated D1 migration tools fit together and which
workflow to choose. It is intentionally more detailed than
[TOOL_GUIDE.md](TOOL_GUIDE.md), but it is not the machine contract.

For exact arguments and response fields, use
[CLIENT-CONTRACT.md](CLIENT-CONTRACT.md). For step-by-step production operating
procedures, use [RUNBOOK.md](RUNBOOK.md).

## Why D1 has a separate workflow

D1 migration operations are deliberately narrower than unrestricted SQL or raw
REST execution. A migration can change durable schema and data, and an
ambiguous provider response can make retrying the same non-idempotent operation
unsafe.

The curated workflow therefore keeps several things bound together:

- the exact target account and database;
- the exact migration bytes and ordered manifest;
- the current migration-ledger prefix;
- the reviewed effect assertion;
- the dry-run plan and approval identity;
- local lease/custody evidence for an in-flight attempt;
- provider response and readback evidence;
- terminal reconciliation and receipt state when the original outcome is
  ambiguous.

Generic `api_mutate` intentionally denies D1 query/raw SQL, import, and time
travel restore operations that could bypass this boundary.

## Choosing the right D1 tool

For ordinary inspection and read-only work, start with:

- `d1_list_databases`
- `d1_get_database`
- `d1_inspect_schema`
- `d1_validate_query`
- `d1_query_read_only`

For bounded row changes that fit the curated write contract, use
`d1_execute_write`.

For database lifecycle changes, use the dedicated curated tools such as
`d1_rename_database` and `d1_delete_database` rather than attempting to recreate
the same lifecycle through generic REST calls.

For migrations:

- `d1_apply_migrations` is retained for dry-run inspection only. It does not
  perform live directory-backed migration mutation.
- `d1_apply_migration_manifest` is the normal live migration path.
- `d1_bootstrap_migration_ledger` is only for establishing the migration ledger
  on a separately selected, genuinely empty database before the first
  migration.
- `d1_reconcile_migration_manifest` is the read-only recovery path after an
  ambiguous manifest apply with retained custody evidence.
- `d1_finalize_migration_reconciliation` turns independently approved
  reconciliation evidence into terminal local receipt/custody state without
  replaying the provider mutation.
- `d1_reconcile_bootstrap_migration_ledger`,
  `d1_finalize_bootstrap_migration_ledger`, and
  `d1_abort_bootstrap_migration_ledger` are the separate bootstrap recovery
  lifecycle.

## Normal manifest workflow

A live migration starts with `d1_apply_migration_manifest` in dry-run mode.
Review the exact target, source manifest, execution manifest, migration-ledger
state, selected effect assertion, and returned plan digest.

A live apply must use the exact approval identity produced by the dry run. The
server rechecks current target and ledger state before issuing the mutation.
The source manifest remains the reviewed source of truth even when a narrowly
versioned execution transform is required for provider compatibility.

A successful apply is not inferred from HTTP status alone. The response and
post-state evidence must satisfy the migration contract, including primary
service and typed mutation metadata. If the server cannot prove the outcome, it
reports reconciliation-required state rather than treating uncertainty as
success or authorizing a retry.

## Exact-byte manifests

Migration authority is byte-sensitive. Do not normalize SQL, path names, case,
comments, whitespace, or assertion identifiers after review and expect an
existing approval to remain valid.

The manifest owns the ordered migration identity and the selected assertion
owns the allowed effect shape. Current assertion families include:

- `schema_create_only_v1` for the established table/index-only contract;
- `schema_create_tables_indexes_views_triggers_v1` for explicitly reviewed
  views and triggers as well as tables and indexes;
- `schema_create_objects_additive_v1` for the closed additive CREATE plus
  bounded `ALTER TABLE ... ADD COLUMN` contract;
- `schema_create_objects_additive_seed_rows_v1` for the additive contract plus
  bounded canonical seed inserts using TEXT and signed INTEGER literals;
- `schema_create_objects_additive_seed_rows_v2` for the separate seed contract
  that additionally admits reviewed canonical SQL `NULL` values.

These are separate contracts, not progressively fuzzy labels. The selected
assertion is carried through planning, reconciliation, terminal finalization,
and replay evidence.

## Foreign-key execution transform

D1 already enforces foreign keys and runs migration queries in an implicit
transaction, so enabling `foreign_keys` from inside that transaction is not a
portable execution step.

For the exact reviewed leading bytes `PRAGMA foreign_keys = ON;\n\n`, the
migration path can preserve the original source manifest while executing the
remainder under the versioned
`drop-leading-pragma-foreign-keys-on-v1` transform. The dry run exposes the
transform identity plus executed-byte and provider-statement digests, and those
values become part of the approved plan.

Near matches do not receive this treatment. Differences in case, whitespace,
comments, duplicate or embedded pragmas, or an empty remainder fail closed
rather than being silently normalized.

## Bootstrap is a separate lifecycle

`d1_bootstrap_migration_ledger` is not a compatibility mode for an existing
application database. It is only for a separately selected database whose
application-owned schema is genuinely empty before its first migration.

The dry run binds the exact account, database, ledger-table identity, canonical
initializer, and stable primary-served empty-state evidence. Live apply repeats
that proof under the same target custody and may issue at most one initializer
mutation.

It does not:

- execute migration SQL;
- add a ledger to a database that already contains application objects;
- repair a partially initialized ledger;
- turn an ambiguous initializer response into permission to retry.

SQLite internals and Cloudflare-reserved `_cf_*` objects are treated separately
from application-owned schema for this empty-target decision. Custom migration
ledger names in reserved `sqlite_*` or `_cf_*` families are rejected.

The exact custody family `migration-ledger-bootstrap-v1` is reserved for this
bootstrap lifecycle. The general manifest apply, reconciliation, and terminal
finalization tools reject that exact family rather than accepting an empty
manifest as a substitute.

## Ambiguous outcomes are not retry authority

The critical recovery rule is simple:

> If a non-idempotent provider mutation may have been dispatched, uncertainty is
> a reconciliation problem, not permission to run the same mutation again.

The D1 migration boundary uses bounded one-attempt provider calls for these
operations. Redirects are not followed. Response bodies are bounded and
strictly decoded. Evidence records distinguish failures before dispatch from
failures after a request may have reached the provider.

That distinction matters:

- a pre-dispatch validation, configuration, or request-construction failure can
  truthfully report zero provider calls;
- a transport or response failure after dispatch is evidence of an attempted
  operation even when no valid response can be decoded;
- malformed, partial, oversized, or otherwise unusable provider evidence does
  not become success and does not become retry authority.

Provider messages are not required as proof. Recovery relies on bounded
structured evidence, response digests, lifecycle state, provider-call counts,
and current readback.

## Manifest reconciliation

Use `d1_reconcile_migration_manifest` only when the exact retained migration
custody evidence for the ambiguous attempt is available. Supply the complete
exact-byte manifest and the required expected state for each prefix.

Reconciliation is read-only. It proves the current primary state against the
reviewed manifest and assertion grammar. It does not replay migration SQL and it
does not retire custody merely because two reads happen to agree.

The response distinguishes terminally provable state from conflicting,
unknown, malformed, non-primary, unstable, or custody-drifted evidence. When
custody cannot be revalidated, a null retention claim means retention was not
proven by that call. It must not be interpreted as evidence that the retained
lease disappeared safely.

When reconciliation reaches a terminal product, record the exact approval
products and use `d1_finalize_migration_reconciliation` for terminal receipt and
custody handling. Finalization re-proves current state and performs no provider
migration write.

## Bootstrap reconciliation

An ambiguous bootstrap initializer uses the bootstrap-specific reconciler, not
the general manifest reconciler.

`d1_reconcile_bootstrap_migration_ledger` binds the original bootstrap target,
plan, initializer, installed schema, lease identity, and bootstrap custody
family. It performs stable primary read-only proof windows. Only the exact
canonical initializer schema with an empty migration ledger can reach the
terminal proof-ready state, and even then the proof establishes convergence,
not attribution to a particular caller.

`d1_finalize_bootstrap_migration_ledger` consumes independently recorded
reconciliation products, re-proves provider state before durable local receipt
persistence and custody retirement, and issues no provider write.

`d1_abort_bootstrap_migration_ledger` is narrower still. It is the terminal path
for marker-aware retained bootstrap custody when the server can prove that the
initializer was never dispatched. It is not an alternative reconciler for an
attempted or ambiguous initializer.

## Seed-row assertions

Seed-row migration assertions deliberately use a closed SQL form. The purpose
is to make the resulting state provable without turning reconciliation into a
general SQL interpreter.

The v1 seed assertion permits bounded canonical inserts of reviewed TEXT and
signed INTEGER literals into a manifest-created table. The v2 assertion is a
separate contract that additionally admits canonical SQL `NULL` values under
its own storage-class and nullability rules.

The exact assertion version remains part of the operation identity through
reconciliation and terminal evidence. Do not relabel a v2 manifest as v1, or
vice versa, to make a plan fit existing evidence.

## Evidence and privacy

Migration recovery responses favor proof metadata over raw provider data.
Depending on the path, evidence can include:

- provider-call and mutation counts;
- chronological provider read/write lifecycle entries;
- captured response sizes and SHA-256 digests;
- query and plan digests;
- current ledger-prefix and state-binding digests;
- custody state and retention classification;
- terminal receipt state.

Raw seed values, response bodies, provider error messages, credentials, and
private paths are not needed as normal recovery evidence and should not be
copied into public issue reports.

## Usage-spike investigations are separate

A D1 cost or usage investigation is not a migration workflow. Start with
`account_billing_usage` for Cloudflare billing usage records, then use
`graphql_analytics_query` for attribution such as D1 analytics groups. Inspect
individual database schemas only after the billing/analytics evidence narrows
the target or time window.

## Where to look next

Use these documents for different levels of detail:

- [TOOL_GUIDE.md](TOOL_GUIDE.md): choose the right tool family.
- [CLIENT-CONTRACT.md](CLIENT-CONTRACT.md): exact public tool arguments and
  response semantics.
- [RUNBOOK.md](RUNBOOK.md): operational procedures, recovery sequencing, and
  release checks.
- [SECURITY_MODEL.md](SECURITY_MODEL.md): credential, approval, and mutation
  safety boundaries.
- [API-PARITY.md](API-PARITY.md): why some generic D1 REST operations are denied
  or redirected to curated workflows.
