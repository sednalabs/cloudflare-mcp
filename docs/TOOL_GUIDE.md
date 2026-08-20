# Tool Guide

This guide maps the MCP tool surface by workflow. For exact argument
requirements, use [CLIENT-CONTRACT.md](CLIENT-CONTRACT.md).

## Discovery and Status

Use these first when orienting a session:

- `health`: runtime status and configured defaults.
- `find_tools`: local tool search for non-hosted deferred-loading clients;
  returns a narrow `openai_allowed_tools` list and optional MCP schemas.
- `api_parity_status`: generic Cloudflare REST API catalog status.
- `capabilities_check`: read-only Cloudflare capability probe.

## Tunnel, DNS, Access, and Publish

Use this family for guarded exposure workflows:

- `list_tunnels`
- `ensure_tunnel`
- `generate_tunnel_ingress`
- `connector_control`
- `list_dns_records`
- `verify_dns_route`
- `list_access_apps`
- `access_get_app`
- `access_verify_hostname_gate`
- `list_access_policies`
- `upsert_dns_cname`
- `upsert_access_app`
- `replace_access_policies`
- `apply_access_allowlist`
- `publish_preflight`
- `lock_first_publish`
- `verify_http_gate`
- `emergency_unpublish`

Prefer `publish_preflight` and `lock_first_publish` over direct DNS mutation
when a hostname is becoming reachable. Policy evaluation should happen before
DNS changes.

## Pages

Use Pages tools for project inspection, domain management, and direct uploads:

- `pages_list_projects`
- `pages_get_project`
- `pages_update_project`
- `pages_list_deployments`
- `pages_get_deployment`
- `pages_trigger_deployment`
- `pages_deploy_directory`
- `pages_retry_deployment`
- `pages_rollback_deployment`
- `pages_list_domains`
- `pages_get_domain`
- `pages_ensure_domain`
- `pages_retry_domain_validation`

Use `pages_deploy_directory` for direct-upload projects. Use
`pages_trigger_deployment` for Git-backed projects.

## D1

Use curated D1 tools instead of generic API calls for database workflows:

- `d1_list_databases`
- `d1_get_database`
- `d1_inspect_schema`
- `d1_validate_query`
- `d1_query_read_only`
- `d1_execute_write`
- `d1_apply_migrations` (dry-run inspection only; live mutation is retired)
- `d1_bootstrap_migration_ledger`
- `d1_reconcile_bootstrap_migration_ledger`
- `d1_finalize_bootstrap_migration_ledger`
- `d1_abort_bootstrap_migration_ledger`
- `d1_apply_migration_manifest`
- `d1_reconcile_migration_manifest`
- `d1_finalize_migration_reconciliation`
- `d1_rename_database`
- `d1_delete_database`

Read/query tools use restricted SQL checks. Write and migration tools preserve
dry-run discipline and fail closed on unsafe or ambiguous state. Use
`d1_apply_migration_manifest` for every live migration; the legacy
directory-backed `d1_apply_migrations` tool refuses live mutation.
The exact family `migration-ledger-bootstrap-v1` belongs only to the dedicated
bootstrap apply/reconcile/finalize/abort lifecycle. All three generic manifest
tools reject it before provider, custody, receipt, or namespace activity.

Use `d1_bootstrap_migration_ledger` only before the first migration on a
separately selected, genuinely empty D1 database. Its dry run binds the exact
account, database, ledger table, canonical initializer, and two matching
primary-served empty-schema reads. Live apply shares the manifest target lease,
repeats that proof, and may issue exactly one ledger-table initializer. It does
not execute migration SQL, add a ledger to a database containing application
objects, repair a partial ledger, or retry after an ambiguous provider result.
Successful post-state proof requires the canonical table to be the only
application-owned object and its filename ledger to remain empty. SQLite
internals and Cloudflare's reserved `_cf_*` objects are provider-owned and do
not make an otherwise empty D1 an application-bearing target. Custom ledger
names in either the `sqlite_*` or `_cf_*` reserved family are rejected. The
single DDL acknowledgement may truthfully carry zero row counts; it must still
prove primary service and `changed_db=true`, after which stable schema and
empty-ledger readback supplies the effect proof.

All bootstrap inventory and ledger reads use the recovery-grade HTTP boundary:
one physical attempt per read, no redirect following, a 16 MiB body cap, and
strict response decoding. Inspect `provider_read_lifecycle` for every logical
read and `response_evidence` for exact body digest/size evidence when bytes were
captured. `provider_calls` counts only attempted HTTP requests, so a
pre-dispatch configuration failure is zero while transport loss after dispatch
is one. Request-builder failures are also pre-dispatch. Every lifecycle and
response entry retains its exact dry-run, live pre-dispatch, ambiguous-write,
or post-write window plus first/second inventory or ledger phase and query
digest even when no body exists. Nested provider causes are permanently
reconciliation-only with `retryable=false` and omit body-derived messages;
this includes initializer write failure. Never infer a hidden retry from two
paired stability reads.

If that one initializer dispatch has an ambiguous result, use
`d1_reconcile_bootstrap_migration_ledger`; do not supply an empty manifest to
the general manifest recovery tool. Bind the exact account/database,
`migration-ledger-bootstrap-v1` custody family, bootstrap plan, lease nonce and
payload, ledger table, canonical initializer, and exact installed schema. The
read-only tool performs two stable primary proof windows. Each window uses two
bounded schema reads followed by two empty-ledger reads. Every read is one HTTP
attempt, never follows redirects, and retains response-byte digest, size, and
request-lifecycle evidence; `provider_calls` counts actual dispatches. Only the same exact
canonical initializer schema with zero ledger rows in both windows returns
`terminal_proof_ready`; attribution remains unknown and initializer retry
remains forbidden.

Use `d1_finalize_bootstrap_migration_ledger` only after independently recording
all four reconciliation digests. Its dry run re-proves those products and
returns a terminal-plan digest. A live call requires that exact approval,
re-proves the provider state before create-only receipt persistence and again
before guarded active -> retiring -> retired custody transitions, and performs
no provider mutation. Ledger absence, any other object, a non-empty ledger,
malformed/non-primary/unstable evidence, changed approval pins, custody drift,
or a receipt conflict is nonterminal: preserve custody and never retry the
initializer. Custody drift reports no stale retain decision; drift after receipt
persistence reports the durable receipt and local mutation while leaving
retirement blocked. The final descriptor-bound readback remains authoritative:
if it fails, its exact true/false/null receipt evidence replaces any earlier
creation-time claim.

Use `d1_abort_bootstrap_migration_ledger` only for marker-aware bootstrap
custody whose exact initializer-attempt receipt is stably absent. This is the
provider-free terminal path for a release failure before any initializer
dispatch, not an alternative reconciler. Dry run returns an approval-bound
terminal plan; live execution persists an exact `not_committed` receipt,
rechecks marker absence, and retires custody. Active, retiring, retired, and
absent physical evidence are classified independently. Exact completed replay
converges with zero provider or local mutations; conflicting receipt identity,
legacy custody, malformed marker evidence, or any durable attempt marker fails
closed. A fresh bootstrap after successful retirement requires a new dry run.

Use `d1_reconcile_migration_manifest` only for exact retained
`active.lease.json` or `retiring.lease.json` evidence after an ambiguous
manifest apply. Supply the complete exact-byte manifest and one complete
expected schema state for every prefix from zero through the full manifest.

For `d1_apply_migration_manifest`, every plan, live, post-apply, and ambiguous
outcome filename-ledger read requires exactly one successful result set with
literal boolean `meta.served_by_primary=true`. Missing, false, non-boolean,
malformed, duplicate, or unstable primary evidence fails closed. After an
ambiguous non-idempotent apply, the tool rereads that evidence and revalidates
the local custody chain before it can report `lease_retained=true`. Lost or
unverifiable custody returns `lease_retained=null` with
`custody_status=lost_or_unverifiable_after_ambiguous_apply`; it prohibits retry
and does not turn an absent local file into permission for a new apply.
For every migration-write result set, success additionally requires literal
`meta.served_by_primary=true`, boolean `meta.changed_db`, and non-negative JSON
integer `meta.changes` and `meta.rows_written`. A non-mutating successful result
(for example a supported PRAGMA in a multi-statement migration) must report
`changed_db=false` with both counts zero. The complete response must contain at
least one `changed_db=true` result and positive aggregate changes and
rows-written totals. Any missing, non-boolean, non-integer, zero-total,
overflowed, failed, or malformed result is `reconciliation_required`, never a
successful apply or authorization to retry.
The tool derives every target allowed by the selected registry assertion from
the manifest and rejects omissions, additions, data-producing CREATE forms,
malformed result metadata, and result sets whose query-bound statement marker
is absent or changed. Use `schema_create_only_v1` for the backward-compatible
table/index-only contract. Use
`schema_create_tables_indexes_views_triggers_v1` only when every prefix also
declares exact view and trigger `sqlite_master` type/name/parent/SQL-digest
evidence. Trigger parents must be tables in the same selected state; views and
triggers do not receive table_xinfo or foreign-key PRAGMA expectations. The
extended registry safely keeps trigger-body semicolons and nested `CASE ...
END` inside one statement while rejecting temporary/schema-qualified objects,
malformed bodies, unsupported top-level effects, and reused identities. It
also supports the separately selected
`schema_create_objects_additive_v1` contract for a closed additive migration:
all of the extended CREATE-object proof, at most one canonical unqualified
`ALTER TABLE ... ADD [COLUMN]` with one bounded column definition per prefix,
and at most one exact `PRAGMA foreign_keys = ON`. The parent must already exist
in the baseline or an earlier prefix. Every expected transition must preserve
the complete prior ordered columns and foreign keys, append the exact next
column, and change only the altered parent's reviewed SQL digest plus explicitly
created objects. A trailing CHECK is accepted only through the bounded
column-local pure-expression grammar: `IS NULL`, literal equality or IN,
`length`, `substr`, `AND`/`OR`, and bounded parentheses. It cannot read another
column, run a subquery, call another function, or introduce another column
constraint or SQL effect. The PRAGMA is classified intent, not a claim about
persistent connection state. No manifest SQL is ever sent to the provider by
this tool.
The two predecessor assertions continue to reject ALTER and PRAGMA unchanged.
Use `schema_create_objects_additive_seed_rows_v1` only for a bounded canonical
top-level seed INSERT on a table created by the supplied manifest. Its closed
form is `INSERT INTO <table> (<explicit columns>) VALUES (<literal tuples>)`:
the table and columns are plain unqualified identifiers, values are canonical
TEXT or signed INTEGER literals, and each target may be seeded once. Every
classified CREATE is unconditional; `IF NOT EXISTS` is rejected because an
incumbent object would make the manifest effect a no-op. The CREATE
must precede the INSERT and every trigger on that target must follow it, even
across manifest entries. CREATE, ALTER, index, trigger, seed membership, and
reuse follow SQLite ASCII case-insensitive identifier identity; expectations
and fixed read queries retain the one reviewed spelling from `CREATE TABLE`.
For baseline tables that the supplied manifest does not create, repeated
case-variant ALTER/index/trigger parents converge on the deterministic first
encountered manifest spelling for derivation and transition lookup. Provider
and expectation spellings are still preserved in the selected fixed proof.
Every `state_expectations`
prefix adds `seed_tables` with the exact target, ordered columns, row count,
and locally derived `rows_sha256`. Seed storage is deliberately conservative:
on non-STRICT tables, TEXT literals require TEXT or BLOB affinity while INTEGER
literals require INTEGER, NUMERIC, or BLOB affinity; on STRICT tables, TEXT
literals require exact TEXT columns and INTEGER literals require exact INT or
INTEGER columns. STRICT BLOB and other unproven pairs are rejected before
custody. The tool first selects the current primary manifest prefix, then
runs two identical complete primary-current proofs that include exact typed seed
row readback. Its full-manifest registry records the CREATE and seed prefix for
every seed target. The selected proof omits a not-yet-created target, requires
an exact empty table projection after CREATE and before INSERT without
referencing columns introduced by a later prefix, and requires the
exact row set at and after INSERT. An unexpected intermediate row stops after
the first complete proof with zero mutations. Terminal reconciliation rederives
and repeats the same selected-prefix proof. Both complete proof ledgers must
equal the exact initial selected ledger, and the two complete snapshots must
also remain canonically equal; two mutually consistent responses at another
prefix are contradictory. Inspect aggregate-safe `selection_binding` for the
selection-query digest, selected-ledger digest and prefix, and both
complete-ledger digests. Responses return aggregate
row-count/digest evidence only; raw
seed values are never returned. Implicit columns, INSERT SELECT, expressions,
NULL/REAL/BLOB values, conflict clauses, qualified or quoted identities,
duplicate rows/targets, other DML, and any readback mismatch fail closed.
Predecessor assertions remain closed to top-level INSERT.
On success, inspect the complete `effect_assertion.scope` object: its
`statement_class` is assertion-specific (`schema_create_only`,
`schema_create_tables_indexes_views_triggers`, or
`schema_create_objects_additive`, or
`schema_create_objects_additive_seed_rows`) and its `schema_object_types` array
is the closed allowed scope for that selected assertion.
The configured `migrations_table` remains reserved across all assertions using
SQLite ASCII case-insensitive identifier equivalence. CREATE object identities,
index/trigger parents, any exact admitted trigger header/body lexical token, and additive
ALTER targets that collide with it fail before custody or provider access.
The bounded evidence retains every word, quoted identifier, and string-literal
value across the complete post-parent trigger header (including `WHEN`) and
body. An exact string-literal collision is deliberately rejected; longer
unrelated token values and unrelated triggers remain supported.
The boundary also requires every fixed result set in both batches to carry exact
`meta.served_by_primary=true` evidence; absent, false, null, non-boolean, or
mixed primary markers are contradictory and cannot support positive
reconciliation. It performs two bounded read-only batches and never retires
custody evidence or authorizes an apply retry. The boundary does not follow
HTTP redirects and returns one chronological `provider_read_lifecycle` entry
per invocation, distinguishing pre-dispatch, attempted-without-response,
response received, partial/complete body read, and captured HTTP status. A
reconciliation-local recursive decoder rejects duplicate object keys in a
successful-status body before
the raw provider JSON can collapse into a value, across the outer envelope and
nested result, metadata, error, and row objects in either order. Rejection keeps
the exact raw digest, size, status, lifecycle, and retained-custody evidence but
never exposes the duplicate key or body content. This does not broaden generic
Cloudflare response paths or the migration-write JSON policy. A
stream failure before any body byte is `not_read`; it is `partially_read` only
after at least one byte was accumulated. Local token/config failure therefore
reports zero provider calls. Validation or
custody-inspection failure before adapter invocation instead reports
`provider_calls=0` with an empty lifecycle array. A null `lease_retained` with
`custody_status=not_inspected` or `inspection_failed` means no retained lease
was acquired or proven by that call; it is not evidence that custody was
removed. Likewise, `custody_status=retained_evidence_unverified` after a
revalidation failure means retain and inspect the named evidence manually;
HTTP 429 and 5xx reads are unavailable evidence and are not retried, even when
their response body is malformed, truncated, or exceeds the byte bound; 401
and 403 are unavailable under the same no-retry rule. HTTP status remains
attached to invalid UTF-8, malformed JSON, partial-read, and oversized evidence.
Post-read ledger/schema/evidence
contradictions keep verified custody and exact provider-call accounting unless
custody itself fails revalidation. Custody is revalidated after every attempted
provider call, including an unavailable/error response; a simultaneous custody
failure preserves the provider classification and response evidence but reports
`lease_retained=null`. When a later call fails, `response_evidence` remains in
provider-call order rather than replacing evidence from an earlier call, but it
contains only captured response bodies. Top-level `provider_read_lifecycle` is
the separate complete invocation chronology, so a second no-response transport
or pre-dispatch failure is retained even though it cannot add a response
summary. Invocation position and count, not response-value equality, determine
that chronology: two byte-identical successful reads remain two evidence and
lifecycle entries, while reprocessing an already merged product is idempotent.
After a completed first read that aggregate operation reports two
provider calls only when the second invocation reaches transport. A second
pre-dispatch failure retains both lifecycle entries but reports one actual
provider call; standalone pre-dispatch failure remains zero provider calls.

Public tool semantic validation runs in target, migrations-table, manifest,
then migration-family order. A failure at any of those boundaries returns the
complete reconciliation envelope with `capability_state=contradictory`,
`custody_status=not_inspected`, `query_sha256=null`, empty response and
lifecycle evidence, both mutation counts zero, `provider_calls=0`, and
`retry_decision=do_not_retry_same_attempt`; it never opens lease custody or
contacts D1. JSON-RPC and generated-schema parse failures occur before semantic
tool execution and remain MCP deserialization errors without fabricated
structured reconciliation evidence. Target validation includes an omitted
`account_id` when no configured default account exists; that condition is
semantic zero-call evidence, not a JSON-RPC or generated-schema failure.

Use `d1_finalize_migration_reconciliation` only after recording and
independently approving the exact terminal plan returned by its dry run. The
tool binds the retained target, original apply plan, read-only reconciliation
plan, expectation proof, fixed query, canonical snapshot, outcome/prefixes,
and distinct request/attempt digests. A live call re-proves the retained state,
performs another primary-current read immediately before create-only receipt
persistence, repeats that read immediately before retirement, and never issues
a provider write. Exact replay of a completed receipt/retirement converges with
zero provider calls; changed, malformed, duplicate, noncanonical, or
retirement-before-receipt evidence fails closed and retains the blocker.
The supplied manifest is also outcome authority: both prefixes must be bounded
by its exact length; `not_committed` requires current equal to original,
`partial_state_converged` requires original less than current less than manifest
length, and `full_state_converged` requires original less than current equal to
manifest length. Canonical v1 and v2 receipt parsing applies the strongest
manifest-independent part of that contract, so restored `not_committed`
receipts require equal prefixes while both converged outcomes require strict
growth. A canonical shape with a contradictory relationship is invalid durable
evidence, including during zero-provider completed-retirement replay.
The terminal response claims custody only after fresh physical readback. A
verified active lease reports `lease_retained=true` with
`lease_decision=retain`; verified retirement reports `lease_retained=false`
with `lease_decision=retired`. Pre-inspection, inspection failure, retiring,
and unverified/drifted custody report `lease_retained=null` with the
corresponding `custody_status` and no fabricated lease decision.
Retired-without-receipt is a verified-retired order violation, not evidence
that an active lease was retained.
The effect assertion must be byte-for-byte identical to the read-only
reconciliation input; terminal dry run and live execution consume the same
complete view/trigger-capable proof when the extended assertion is selected.

For D1 usage-spike investigations, start with `account_billing_usage` to read
Cloudflare billing usage records, then use `graphql_analytics_query` for
Cloudflare Analytics GraphQL attribution such as `d1AnalyticsAdaptiveGroups` or
`d1QueriesAdaptiveGroups`. Only inspect D1 table schemas after the analytics
result narrows the database, query, or time window.

## WAF and Security Events

Use these before composing raw Rulesets API or GraphQL calls:

- `waf_ruleset_summary`
- `waf_security_events_summary`
- `waf_rule_activity`

`waf_ruleset_summary` reads the Ruleset Engine entrypoints for WAF custom
rules, managed rules, and rate limiting rules. It accepts aliases such as
`custom`, `managed`, and `ratelimit`, and returns compact rule IDs,
descriptions, actions, enabled state, expressions, and deployment metadata.

`waf_security_events_summary` runs a curated Cloudflare Analytics GraphQL query
against the Security Events dataset, `firewallEventsAdaptive`, and returns
grouped evidence plus recent samples. Security Events represent individual
events, not unique HTTP requests, and Cloudflare may sample large windows; use
narrower windows for spike triage. When grouped GraphQL authz degrades, the
response may include `diagnostics.authz_classification` so callers can tell
whether the likely issue is wrong context, grouped-only access loss, or a
broader entitlement or product restriction.

`waf_rule_activity` combines the two: it looks for a rule ID in current WAF
Rulesets and queries recent Security Events for that rule. Use it for questions
like "what rule blocked this path?" or "is this rule still firing?"

## Workers and Bindings

Use these to inspect Workers, settings, bindings, and event telemetry:

- `list_workers`
- `workers_list_scripts`
- `get_worker_settings`
- `workers_get_script_settings`
- `workers_upload_script`
- `patch_worker_settings`
- `workers_list_tails`
- `workers_observability_query_events`
- `workers_observability_list_keys`
- `workers_observability_list_values`
- `bindings_discover`

Workers Observability tools accept optional `script_name`, `datasets`, and
`filters` so operators can start broad and narrow down without switching to raw
API calls.

Use `workers_upload_script` when the deploy boundary is the Worker script body
itself. It accepts a single module file/content or a prebuilt multipart Worker
bundle, returns a dry-run confirmation token, and summarizes script/metadata
evidence with SHA-256 digests plus metadata keys rather than raw metadata
values. Apply requires the dry-run token, reads back Worker settings, and
reports `readback_verification`; a different non-empty `main_module` fails
closed. For create-only module uploads, settings may legitimately return a
null `main_module`; the tool then requires exhaustive, stable, etag-bound
Worker listing/version-detail evidence with a present named-handler array;
handler names and export members must be unique, nonblank, and byte-exact
(leading or trailing whitespace fails closed).
The default and named handler arrays may each be empty, but at least one valid
entrypoint must exist overall.
Version pagination is read from the outer `result_info` envelope metadata; an
optional nested `pagination` object must agree when present.
Malformed, incomplete, ambiguous, or conflicting evidence fails closed. Use
Wrangler only to generate a bundle when the project already documents that
build path.

Pass `create_only: true` when the script name must be unused: the apply request
uses Cloudflare's atomic `If-None-Match: *` precondition, and a pre-existing
script returns `workers.upload_create_only_conflict` without retrying or
overwriting it. The create-only flag is included in the dry-run confirmation
authority; omit it (the default) for the existing update behavior. Transport,
timeout, response-read/decoding, retryable 5xx, and success-without-result
responses return
`workers.upload_create_only_outcome_uncertain` with `retryable:false`; read back
the Worker and reconcile provider evidence before retrying or claiming
creation. These guards apply only when `create_only:true`.

Use `bindings_discover` to find D1, Queues, Worker, and Pages resources that
may need to be wired into an application.

## Queues

Use Queue tools for operational health and backlog investigation:

- `queues_list`
- `queues_get`
- `queues_get_metrics`
- `queues_list_consumers`
- `queues_health`

`queues_health` combines settings, realtime backlog metrics, consumer status,
purge status, and configured DLQ readback.

## R2

Use R2 tools for S3-compatible private object access:

- `r2_inspect_object`
- `r2_get_object`
- `r2_put_object`

Use file response mode for large or binary objects that should not be returned
inline through an MCP response.

## Analytics Engine

Use Analytics Engine tools for read-only SQL workflows:

- `analytics_engine_list_datasets`
- `analytics_engine_describe_schema`
- `analytics_engine_validate_query`
- `analytics_engine_query`

These tools are designed around documented dataset schema hints and restricted
read-only query execution.

## Cache, Redirects, and Email Routing

Cache tools:

- `cache_purge`
- `cache_zone_setting`
- `cache_rules`
- `cache_reserve`
- `cache_tiered`
- `cache_variants`
- `cache_origin_regions`

Bulk Redirect tools:

- `bulk_redirects_list_lists`
- `bulk_redirects_get_list`
- `bulk_redirects_list_items`
- `bulk_redirects_create_list`
- `bulk_redirects_update_list`
- `bulk_redirects_import_items`
- `bulk_redirects_get_operation`
- `bulk_redirects_get_ruleset`
- `bulk_redirects_attach_list_to_ruleset`

Email Routing tools:

- `email_routing_get_settings`
- `email_routing_get_dns`
- `email_routing_list_rules`
- `email_routing_get_rule`
- `email_routing_get_catch_all`
- `email_routing_list_addresses`
- `email_routing_get_address`

Broad cache and redirect mutations should be treated as operationally
sensitive: run dry-run first and keep correlation IDs.

## Account API Tokens

`account_api_tokens` is a curated tool for account-owned API token management.
Read actions do not prompt when elicitation is enabled; create, update, delete,
and roll apply calls are dangerous operations and can be approval-gated.

Use `account_api_token_permission_plan` before updating an existing token's
permission groups. It is read-only: it reads the current token and permission
group catalog, resolves exact permission group names/ids/scopes, reports what
would be added or removed, and returns the safe `account_api_tokens` update
payload with `dry_run=true`. This avoids the common full-body `PUT` trap where
an operator accidentally submits only the new scopes and drops existing ones.
If a token has multiple policies, the planner refuses to guess and asks for a
zero-based `policy_index`.

For `bot-management-for-a-zone-update-config`, read the account-owned token
first and pass its fresh permission-group names in `api_mutate.token_permissions`.
The operation requires the complete pair `Bot Management Write` and
`Zone Settings Write`. The mutation dry-run does not emit a confirmation token
until that pair is present. If one is missing, follow the returned
`account_api_token_permission_plan` and guarded `account_api_tokens` calls,
read the token back, then rerun the mutation dry-run.

## Generic Cloudflare REST API Tools

Use generic parity tools when no curated tool exists:

1. `api_find_operations`
2. `api_get_operation`
3. `api_prepare_call`
4. `api_read`
5. `api_mutate`

If `api_get_operation` reports a preferred curated tool, use that curated tool.
Curated tools encode workflow-specific safety, dry-run shape, and readback
verification.

The generic `worker-script-put-content` operation is denied by default. Use
`workers_upload_script` for Worker module or multipart bundle uploads so the
upload digest, confirmation token, and post-upload readback stay bound together.

## External Service Bridge

`portal_agent_request` is an allowlisted external service bridge. It is useful
for deployments that want a controlled MCP tool to call approved operator
endpoints with server-held credentials.

Public examples intentionally use generic endpoint placeholders. Configure the
allowlist and credentials for your own environment.
