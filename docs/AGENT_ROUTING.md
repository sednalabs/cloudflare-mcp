# Agent Routing Guide

This guide tells agents which Cloudflare surface to use first. It keeps
`cloudflare-mcp` focused on guarded operator workflows while letting official
Cloudflare MCP servers and CLIs do the jobs they are better suited for.

Last verified against Cloudflare's managed MCP server documentation on
2026-06-20:

- `https://developers.cloudflare.com/agents/model-context-protocol/cloudflare/servers-for-cloudflare/`
- `https://github.com/cloudflare/mcp`
- `https://github.com/cloudflare/mcp-server-cloudflare`

Codex/agent profile template:

- `packaging/codex/cloudflare-managed-mcp.example.toml`

## Default Decision Rules

Use this server first when the task needs one of its curated workflows:

- Dry-run/apply/readback discipline for production-affecting changes.
- Local credential custody or private self-hosted operation.
- Policy gates, confirmation tokens, elicitation approval, or audit metadata.
- A known tool family documented in `docs/CLIENT-CONTRACT.md`.
- Toolkit conformance coverage for strict inventory, auth, resources,
  elicitation, error envelopes, or mutation audit behavior.

Use Cloudflare's official managed MCP servers first when the task needs broad or
current Cloudflare coverage outside this server's curated workflows:

- Code Mode API reach across the full Cloudflare API through `search()` and
  `execute()` at `https://mcp.cloudflare.com/mcp`.
- Current Cloudflare documentation at `https://docs.mcp.cloudflare.com/mcp`.
- Product-specific exploration such as Workers Bindings, Workers Builds,
  Observability, Radar, Browser Run, Logpush, AI Gateway, Audit Logs,
  DNS Analytics, Digital Experience Monitoring, CASB, GraphQL, or Agents SDK
  documentation.

Use Wrangler, `cf`, or other Cloudflare-documented CLIs first when Cloudflare
documents the local developer workflow around that CLI:

- Local Workers development and deploy loops.
- Wrangler-managed Pages and Workers build artifacts.
- D1 migrations and local database workflows.
- Commands where the CLI owns project layout, generated files, or interactive
  developer state.

## Workflow Map

| Workflow | Start Here | Fallback |
| --- | --- | --- |
| Tunnel, DNS, Access publish flow | `cloudflare-mcp` curated publish tools | Official API MCP for rare fields not modeled locally |
| Pages deploy with readback | `pages_deploy_directory` | Wrangler for canonical project build/dev loops |
| D1 discovery, guarded writes, migrations | `cloudflare-mcp` D1 tools | Wrangler for local migration authoring and project state |
| R2 bounded reads or writes | `cloudflare-mcp` R2 tools | Official API MCP for unmodeled admin endpoints |
| Worker script upload with digest evidence | `workers_upload_script` | Wrangler for normal developer deploy workflow |
| Worker settings and bindings readback | `get_worker_settings`, `patch_worker_settings`, bindings tools | Workers Bindings managed MCP |
| Workers Observability events | `workers_observability_*` tools when available | Observability managed MCP |
| Billing and usage spike attribution | `account_billing_usage`, then `graphql_analytics_query` | GraphQL or official API MCP for newer datasets |
| WAF investigation | `waf_ruleset_summary`, `waf_security_events_summary`, `waf_rule_activity` | GraphQL MCP or official API MCP for custom analytics |
| WAF mutation planning | Curated dry-run/apply tool when present, otherwise generic `api_prepare_call` plus review | Official API MCP only for discovery, not final guarded apply |
| Browser rendering | Browser Run managed MCP | Cloudflare REST API only when a guarded local workflow exists |
| Audit logs, Logpush, DNS Analytics, Radar | Matching managed MCP server | Official API MCP for one-off endpoint reach |
| Current Cloudflare docs or schema discovery | Cloudflare Docs managed MCP, Code Mode API MCP | Local `api_find_operations` for committed REST catalog checks |

## Managed MCP Profile Set

Use the checked-in profile template to place official Cloudflare MCPs beside
this server in an agent profile. Enable only the endpoints needed for the
current operator lane:

| Profile key | Managed endpoint | Prefer for |
| --- | --- | --- |
| `cloudflare-api` | `https://mcp.cloudflare.com/mcp` | Broad current Cloudflare API discovery through Code Mode `search()` and `execute()` |
| `cloudflare-docs` | `https://docs.mcp.cloudflare.com/mcp` | Current Cloudflare reference docs |
| `cloudflare-agents-docs` | `https://agents.cloudflare.com/mcp` | Agents SDK docs and MCP protocol guidance |
| `cloudflare-bindings` | `https://bindings.mcp.cloudflare.com/mcp` | Workers bindings, storage, AI, and compute primitive exploration |
| `cloudflare-builds` | `https://builds.mcp.cloudflare.com/mcp` | Workers Builds insight and management |
| `cloudflare-observability` | `https://observability.mcp.cloudflare.com/mcp` | Workers logs and analytics exploration |
| `cloudflare-radar` | `https://radar.mcp.cloudflare.com/mcp` | Internet traffic trends, URL scans, and Radar utilities |
| `cloudflare-browser` | `https://browser.mcp.cloudflare.com/mcp` | Browser rendering, page fetches, markdown conversion, and screenshots |
| `cloudflare-logs` | `https://logs.mcp.cloudflare.com/mcp` | Logpush job health summaries |
| `cloudflare-ai-gateway` | `https://ai-gateway.mcp.cloudflare.com/mcp` | AI Gateway logs and prompt/response lookup |
| `cloudflare-autorag` | `https://autorag.mcp.cloudflare.com/mcp` | AI Search and AutoRAG document search |
| `cloudflare-auditlogs` | `https://auditlogs.mcp.cloudflare.com/mcp` | Audit log queries and reports |
| `cloudflare-dns-analytics` | `https://dns-analytics.mcp.cloudflare.com/mcp` | DNS performance and troubleshooting analytics |
| `cloudflare-dex` | `https://dex.mcp.cloudflare.com/mcp` | Digital Experience Monitoring insight |
| `cloudflare-casb` | `https://casb.mcp.cloudflare.com/mcp` | Cloudflare One CASB misconfiguration review |
| `cloudflare-graphql` | `https://graphql.mcp.cloudflare.com/mcp` | Cloudflare GraphQL analytics exploration |

## Auth And Smoke Expectations

Cloudflare's managed MCPs use Streamable HTTP at `/mcp`. Interactive clients
should authorize with OAuth and grant the narrowest permissions needed for the
task. Automation can pass a Cloudflare bearer token with the required scopes in
the `Authorization` header, but this repository does not check tokens into
profile templates.

The managed endpoints are not proof of authorization until an MCP client has
completed OAuth or attached an appropriate bearer token. On 2026-06-20,
unauthenticated JSON-RPC `initialize` smoke checks returned:

- `https://docs.mcp.cloudflare.com/mcp`: `200 text/event-stream`, initialized.
- `https://mcp.cloudflare.com/mcp`: `401 invalid_token`.
- `https://graphql.mcp.cloudflare.com/mcp`: `401 invalid_token`.
- `https://auditlogs.mcp.cloudflare.com/mcp`: `401 invalid_token`.

That is expected: the docs endpoint can answer public documentation requests,
while account/API endpoints require Cloudflare authorization before read-only
tool calls will succeed. Local `mcp-probe` may also reject these public hosts if
its allowlist does not include them; in that case use an allowlisted probe
profile or a direct JSON-RPC `initialize` smoke with no credentials.

## Guardrails

Do not replace a curated tool with generic `api_mutate` only because the REST
endpoint exists. Curated tools are allowed to be narrower than the full API when
they provide safer planning, policy checks, readback, or audit fields.

Do not force every Cloudflare API endpoint into this repository. Generic parity
belongs in the committed REST catalog and guarded executor; broad current API
exploration belongs in Cloudflare's managed Code Mode server.

Do not use official managed MCPs as the final apply path for a workflow that
requires this server's approval gate, confirmation token, policy invariant, or
post-apply readback. Use them to discover the endpoint or schema, then encode
the production-affecting workflow here when it needs durable guarded operation.

When choosing a path, record enough evidence for the next agent:

- MCP server and tool used.
- Source commit or managed server URL.
- Dry-run output, confirmation token policy, and readback result for mutations.
- Release provenance manifest or binary hash when relying on a local installed
  binary.
