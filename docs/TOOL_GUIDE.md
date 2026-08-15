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
- `d1_apply_migrations`
- `d1_apply_migration_manifest`
- `d1_reconcile_migration_manifest`
- `d1_finalize_migration_reconciliation`
- `d1_rename_database`
- `d1_delete_database`

Read/query tools use restricted SQL checks. Write and migration tools preserve
dry-run discipline and fail closed on unsafe or ambiguous state.

Use `d1_reconcile_migration_manifest` only for exact retained
`active.lease.json` or `retiring.lease.json` evidence after an ambiguous
manifest apply. Supply the complete exact-byte manifest and one complete
expected schema state for every prefix from zero through the full manifest.
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
On success, inspect the complete `effect_assertion.scope` object: its
`statement_class` is assertion-specific (`schema_create_only`,
`schema_create_tables_indexes_views_triggers`, or
`schema_create_objects_additive`) and its `schema_object_types` array is the
closed allowed scope for that selected assertion.
The configured `migrations_table` remains reserved across all assertions using
SQLite ASCII case-insensitive identifier equivalence. CREATE object identities,
index/trigger parents, any exact admitted trigger-body identifier, and additive
ALTER targets that collide with it fail before custody or provider access.
Exact tokenized matching ignores string literals and does not reject longer
unrelated names; unrelated triggers remain supported.
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
