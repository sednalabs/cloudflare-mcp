# Tool Guide

This guide maps the MCP tool surface by workflow. For exact argument
requirements, use [CLIENT-CONTRACT.md](CLIENT-CONTRACT.md).

## Discovery and Status

Use these first when orienting a session:

- `health`: runtime status and configured defaults.
- `find_tools`: local tool search for deferred-loading clients.
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
- `d1_rename_database`
- `d1_delete_database`

Read/query tools use restricted SQL checks. Write and migration tools preserve
dry-run discipline and fail closed on unsafe or ambiguous state.

## Workers and Bindings

Use these to inspect Workers, settings, bindings, and event telemetry:

- `list_workers`
- `workers_list_scripts`
- `get_worker_settings`
- `workers_get_script_settings`
- `patch_worker_settings`
- `workers_list_tails`
- `workers_observability_query_events`
- `workers_observability_list_keys`
- `workers_observability_list_values`
- `bindings_discover`

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

## External Service Bridge

`portal_agent_request` is an allowlisted external service bridge. It is useful
for deployments that want a controlled MCP tool to call approved operator
endpoints with server-held credentials.

Public examples intentionally use generic endpoint placeholders. Configure the
allowlist and credentials for your own environment.
