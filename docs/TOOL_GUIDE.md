# Tool Guide

This guide answers a narrow question: **which `cloudflare-mcp` tool or tool
family should I use for this task?**

For exact arguments and response fields, use
[CLIENT-CONTRACT.md](CLIENT-CONTRACT.md). For production operating procedures,
use [RUNBOOK.md](RUNBOOK.md). For deciding whether the local server or an
official Cloudflare MCP is the better surface, use
[AGENT_ROUTING.md](AGENT_ROUTING.md).

The local server is intentionally not a complete first-class wrapper around
every Cloudflare product. Use curated tools where they add an operator workflow
or a meaningful Rust MCP Toolkit conformance/incubation case. Use the guarded
`api_*` fallback for appropriate REST operations without a curated owner, and
use Cloudflare's official MCPs when they already provide the better surface.

## Session discovery and authentication

Use these when orienting a session or checking the upstream credential state:

- `health`: runtime status and configured defaults.
- `find_tools`: local tool search for clients that do not provide hosted tool
  search/deferred loading.
- `capabilities_check`: read-only Cloudflare capability probe.
- `api_parity_status`: status of the committed generic REST catalog.
- `cloudflare_auth_status`: current upstream OAuth grant status.
- `cloudflare_auth_login`: begin the configured Cloudflare browser
  authorization flow.
- `cloudflare_auth_probe`: verify the current upstream grant against Cloudflare.
- `cloudflare_auth_logout`: clear the local upstream grant after explicit
  confirmation.

MCP client authentication and Cloudflare upstream authorization are separate
boundaries. See [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Tunnel, DNS, Access, and publish

Use this family for guarded hostname exposure and Zero Trust publication:

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

Prefer `publish_preflight` and `lock_first_publish` when a hostname is becoming
reachable. They exist so policy and Access checks can happen before the DNS
commitment point. Use `emergency_unpublish` for the narrow idempotent removal
path rather than composing an improvised recovery sequence.

## Pages

Use Pages tools for project inspection, deployments, direct uploads, rollback,
and custom domains:

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

Use `pages_deploy_directory` when the exact local build directory is part of the
operation. Use `pages_trigger_deployment` for an existing Git-backed deployment
flow. Wrangler remains the better starting point when it owns the local build
or development loop.

## D1

Use curated D1 tools for database inspection and governed existing-target
writes:

- `d1_list_databases`
- `d1_get_database`
- `d1_inspect_schema`
- `d1_validate_query`
- `d1_query_read_only`
- `d1_execute_write`
- `d1_rename_database`
- `d1_delete_database`

For migrations and recovery:

- `d1_apply_migrations`: dry-run inspection only; live directory-backed
  mutation is retired.
- `d1_bootstrap_migration_ledger`: establish the ledger on a separately
  selected, genuinely empty database before its first migration.
- `d1_reconcile_bootstrap_migration_ledger`: read-only recovery after an
  ambiguous bootstrap initializer.
- `d1_finalize_bootstrap_migration_ledger`: terminal receipt/custody handling
  after independently approved bootstrap reconciliation.
- `d1_abort_bootstrap_migration_ledger`: terminal zero-dispatch bootstrap path
  when marker evidence proves the initializer was never attempted.
- `d1_apply_migration_manifest`: normal exact-byte live migration workflow.
- `d1_reconcile_migration_manifest`: read-only recovery after an ambiguous
  manifest apply with retained custody.
- `d1_finalize_migration_reconciliation`: terminal receipt/custody handling
  after independently approved manifest reconciliation.

Do not retry an ambiguous non-idempotent migration merely because the provider
response was missing or malformed. The curated workflow treats uncertainty as
reconciliation work, not retry authority.

The migration contract includes exact-byte manifests, versioned effect
assertions, bounded provider evidence, retained custody, and terminal recovery.
Those details no longer live in this tool-selection guide. See
[D1_MIGRATIONS.md](D1_MIGRATIONS.md) for the conceptual migration/recovery map,
[CLIENT-CONTRACT.md](CLIENT-CONTRACT.md) for exact public tool semantics, and
[RUNBOOK.md](RUNBOOK.md) for operating procedures.

For D1 usage or billing investigations, start with `account_billing_usage`, then
use `graphql_analytics_query` for attribution before inspecting individual
schemas.

## WAF and Security Events

Use the curated read helpers before composing raw Rulesets or Analytics GraphQL
calls:

- `waf_ruleset_summary`
- `waf_security_events_summary`
- `waf_rule_activity`

For a governed WAF mutation, use:

1. `waf_ruleset_plan_change` to read current state, build the stable diff, check
   list/rule constraints, and produce the required confirmation identity;
2. `waf_ruleset_apply_change` to apply the approved plan and perform readback.

Use the official Cloudflare API or GraphQL MCP when the task is broader
exploration and the local plan/apply/readback lifecycle is not required.

## Workers and bindings

Use these tools for Worker inspection, settings, uploads, tails, observability,
and binding discovery:

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

Use `workers_upload_script` when the exact Worker artifact is the deploy
boundary. The dry run binds the upload evidence and confirmation identity; the
apply path performs settings/readback checks. Use `create_only: true` when the
script name must not already exist.

Cloudflare's official Workers Bindings MCP is generally the better surface for
KV, Hyperdrive, R2 bucket, and ordinary binding resource lifecycle work. The
official Workers Builds MCP is the better surface for build history/logs. See
[AGENT_ROUTING.md](AGENT_ROUTING.md).

## Queues

Use Queue tools for queue inspection and operational health:

- `queues_list`
- `queues_get`
- `queues_get_metrics`
- `queues_list_consumers`
- `queues_health`

`queues_health` combines queue settings, backlog metrics, consumer status,
purge status, and configured DLQ readback into one operator-oriented view.

## R2 object access

Use the local R2 tools for bounded S3-compatible private object access:

- `r2_inspect_object`
- `r2_get_object`
- `r2_put_object`

Use file response mode for large or binary objects that should not be returned
inline through an MCP response. For R2 bucket lifecycle management, prefer the
official Workers Bindings MCP unless a separate local workflow is needed.

## Analytics Engine

Use these for read-only Analytics Engine SQL workflows:

- `analytics_engine_list_datasets`
- `analytics_engine_describe_schema`
- `analytics_engine_validate_query`
- `analytics_engine_query`

The validation/query pair is designed to keep the local path read-only rather
than expose arbitrary mutation semantics.

## Billing and GraphQL analytics

Use:

- `account_billing_usage` for account billing/pay-as-you-go usage records;
- `graphql_analytics_query` for read-only Cloudflare Analytics GraphQL
  attribution and product analytics.

Treat billing records and analytics as different evidence sources. Use billing
for what was charged/recorded and analytics for explaining where activity came
from.

## Cache

Curated cache tools include:

- `cache_purge`
- `cache_zone_setting`
- `cache_rules`
- `cache_reserve`
- `cache_tiered`
- `cache_variants`
- `cache_origin_regions`

Broad cache mutations can have large blast radius. Use dry-run planning where
supported and keep correlation IDs/readback evidence for production changes.

## Bulk Redirects

Use:

- `bulk_redirects_list_lists`
- `bulk_redirects_get_list`
- `bulk_redirects_list_items`
- `bulk_redirects_create_list`
- `bulk_redirects_update_list`
- `bulk_redirects_import_items`
- `bulk_redirects_get_operation`
- `bulk_redirects_get_ruleset`
- `bulk_redirects_attach_list_to_ruleset`

Use the operation/status read helpers to confirm asynchronous import or ruleset
attachment outcomes rather than assuming the initial request completed the
whole workflow.

## Email Routing

Read-oriented Email Routing tools include:

- `email_routing_get_settings`
- `email_routing_get_dns`
- `email_routing_list_rules`
- `email_routing_get_rule`
- `email_routing_get_catch_all`
- `email_routing_list_addresses`
- `email_routing_get_address`

Use these for inspection and evidence gathering before falling back to broader
API access for unsupported operations.

## Account API tokens

`account_api_tokens` is the curated account-owned API-token lifecycle tool.
Read actions can be used for inspection; create, update, delete, and roll apply
calls are dangerous operations and can be elicitation-gated.

Use `account_api_token_permission_plan` before changing permission groups on an
existing token. It resolves the current policy and permission-group catalog and
returns a safe update dry run rather than encouraging a partial full-body `PUT`
that could accidentally remove existing permissions.

Some generic API operations also require an explicit permission preflight. For
example, the Bot Management zone update requires both `Bot Management Write`
and `Zone Settings Write` to be verified before `api_mutate` will expose an
apply confirmation token.

## Generic Cloudflare REST API

Use the generic parity workflow when no curated tool owns the operation and the
operation is allowed by local policy:

1. `api_find_operations`
2. `api_get_operation`
3. `api_prepare_call`
4. `api_read`
5. `api_mutate`

`api_get_operation` can identify a preferred curated tool. Follow that routing
when present.

`api_mutate` is not an unrestricted escape hatch. It uses dry-run and
confirmation semantics, respects read-only mode and elicitation policy, and
denies selected high-risk or workflow-owning operations. In particular, generic
Worker script upload and several D1 existing-target operations are blocked so
they cannot bypass the narrower curated lifecycle.

See [API-PARITY.md](API-PARITY.md) for the catalog and deny-policy model.

## External service bridge

`portal_agent_request` is an allowlisted external-service bridge for deployments
that need one controlled MCP tool to call approved operator endpoints with
server-held credentials.

Public examples intentionally use generic placeholders. Configure the endpoint
allowlist and credentials for your own deployment, and do not treat the bridge
as arbitrary HTTP access.

## When the official MCP is the better tool

Do not infer that a local tool should exist simply because a Cloudflare product
exists. Cloudflare's managed MCP family is normally the better choice for
current documentation, broad/new API discovery, Workers Builds, KV and
Hyperdrive lifecycle, Browser Run, Radar, Audit Logs, Logpush, AI Gateway,
AutoRAG, DNS Analytics, DEX, CASB, and sandbox containers.

A local implementation can still make sense when it adds either:

- a concrete self-hosted operator workflow or guardrail; or
- a meaningful real-world conformance/incubation case for a reusable Rust MCP
  Toolkit capability that is intended to be upstreamed.

See [PROJECT_SCOPE.md](PROJECT_SCOPE.md) and
[CONFORMANCE_DOGFOOD.md](CONFORMANCE_DOGFOOD.md) for that contribution rule.
