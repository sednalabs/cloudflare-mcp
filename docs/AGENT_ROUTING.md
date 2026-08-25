# Agent Routing Guide

This guide tells agents which Cloudflare surface to use first. It keeps
`cloudflare-mcp` focused on useful self-hosted workflows and deliberate Rust MCP
Toolkit integration/conformance work while letting Cloudflare's official managed
MCP servers and CLIs do the jobs they are better suited for.

The governing distinction is:

> Use Cloudflare's managed MCPs for broad/current API access and specialist
> product surfaces. Use `cloudflare-mcp` when the local implementation adds a
> useful operator workflow, or when a realistic Cloudflare workload is being
> used deliberately to develop and stress-test reusable Rust MCP Toolkit
> behavior.

## Upstream reference snapshot

The managed MCP inventory and Code Mode description in this guide were refreshed
on 2026-08-25 against:

- `cloudflare/mcp` at
  `75c4dbc005e2ee14b937b18089a7880062264351`;
- `cloudflare/mcp-server-cloudflare` at
  `08d743654176c7e79921a5d596d17678ec900f39`.

Managed endpoints can evolve independently of these repository commits. Use the
Cloudflare Docs MCP and Code Mode API MCP for current discovery when freshness
matters.

See [OFFICIAL_MCP_COMPARISON.md](OFFICIAL_MCP_COMPARISON.md) for the full
architectural comparison and [PROJECT_SCOPE.md](PROJECT_SCOPE.md) for the
project-level decision rule.

Codex/agent profile template:

- `packaging/codex/cloudflare-managed-mcp.example.toml`

## Default Decision Rules

Use this server first when the task needs one of its curated workflows:

- Dry-run/apply/readback discipline for production-affecting changes.
- Local credential custody or private self-hosted operation.
- Local artifact access for Pages, Workers, D1 migration material, or similar
  exact-byte workflows.
- Policy gates, confirmation tokens, elicitation approval, or audit metadata.
- A known tool family documented in `docs/CLIENT-CONTRACT.md`.
- A global read-only profile that must hide and deny write tools even when the
  upstream Cloudflare credential has write permission.
- Toolkit conformance coverage for strict inventory, large-catalog discovery,
  deferred loading, auth, resources, elicitation, error envelopes, mutation
  audit behavior, or release provenance.

Use Cloudflare's official Code Mode API MCP first when the task needs:

- broad current API reach across many Cloudflare products;
- a rare/new endpoint that may not yet be in the committed local catalog;
- low-context API exploration through the official `docs`, `search`, and
  `execute` Code Mode surface;
- fast schema/endpoint discovery before deciding whether a recurring workflow or
  useful Toolkit stress case deserves a local implementation.

Use Cloudflare's official domain-specific MCPs first when the task needs a
purpose-built managed surface such as:

- current Cloudflare documentation;
- Workers Bindings, including KV/R2 bucket/D1/Hyperdrive resource management;
- Workers Builds and build logs;
- Workers Observability;
- sandbox containers;
- Browser Run;
- Radar;
- Logpush;
- AI Gateway;
- AutoRAG;
- Audit Logs;
- DNS Analytics;
- Digital Experience Monitoring;
- Cloudflare One CASB;
- GraphQL analytics;
- Cloudflare Blog search/read.

Use Wrangler, `cf`, or other Cloudflare-documented CLIs first when Cloudflare
documents the local developer workflow around that CLI:

- Local Workers development and deploy loops.
- Wrangler-managed Pages and Workers build artifacts.
- D1 migration authoring and local database workflows.
- Commands where the CLI owns project layout, generated files, or interactive
  developer state.

## When to add a local tool

Do not add a tool just because Cloudflare exposes an endpoint. A local
implementation should normally have at least one concrete reason to exist.

### Operator reason

Examples include:

- a safety or approval rule that must be enforced locally;
- a multi-step workflow that benefits from one stable plan/apply/readback path;
- local artifact handling or exact-input hashing;
- a self-hosted credential or network boundary;
- verification or recovery behavior that the raw endpoint does not provide.

### Toolkit reason

Overlap can also be deliberate when the Cloudflare implementation provides a
meaningful real-world integration or stress case for reusable Rust MCP Toolkit
behavior. The contribution should identify the reusable capability being tested,
exercise it through a realistic MCP boundary, and move the provider-neutral
mechanism into `mcp-toolkit-rs` once it is sufficiently proven.

Examples include large-catalog discovery, deferred loading, strict tool
inventory, read-only filtering, auth, elicitation, resources, structured errors,
mutation evidence, and release provenance.

If neither an operator reason nor a Toolkit reason applies, routing the task to
Cloudflare's managed MCP is normally less code for this repository to own and
keeps the local surface easier to review.

## Do not confuse endpoint reach with workflow ownership

A generic API path being able to call an endpoint does not mean it should own
the final production mutation.

Examples:

- the official API MCP can call DNS and Access endpoints, but this repository's
  publish workflow additionally checks the Access/publish gate and provides
  readback/emergency-unpublish semantics;
- the official API MCP can call Rulesets endpoints, but a governed WAF change
  should use `waf_ruleset_plan_change` followed by
  `waf_ruleset_apply_change` when the stable diff/confirmation/readback
  lifecycle is required;
- the official API MCP can reach Worker upload APIs, but this repository blocks
  generic Worker content upload and routes that operation through
  `workers_upload_script` so the artifact digest participates in admission;
- the official API MCP can reach D1 query/import/restore APIs, but this
  repository deliberately restricts some of those generic operations so they
  cannot bypass the curated migration and row-write boundary.

Use official MCPs freely for discovery and managed specialist capabilities. Do
not use them as the final apply path when the requirement specifically depends
on a local guardrail they do not provide as part of the tool contract.

Toolkit incubation is a separate reason to implement an overlapping path. It
should not be confused with production routing: the fact that a local tool is a
useful Toolkit stress case does not automatically make it the preferred user
path for that Cloudflare product.

## Workflow Map

| Workflow | Start here | Final/guarded path when needed |
| --- | --- | --- |
| Current Cloudflare docs | Cloudflare Docs MCP | N/A |
| Newly released or obscure REST API | Cloudflare Code Mode API MCP | Code Mode, or curate/refresh locally before recurring governed use |
| Tunnel, DNS, Access publish flow | `cloudflare-mcp` curated publish tools | `cloudflare-mcp` |
| Pages direct deploy with local artifact/readback | `pages_deploy_directory` | `cloudflare-mcp` |
| Pages/Workers local development loop | Wrangler | Wrangler, then guarded local deploy path if policy requires |
| D1 discovery/read/query | `cloudflare-mcp` or Workers Bindings MCP | Choose based on local policy/credential needs |
| D1 guarded row writes/migrations | `cloudflare-mcp` D1 tools | `cloudflare-mcp` |
| KV namespace lifecycle | Workers Bindings managed MCP | Workers Bindings unless a local operator or Toolkit-development reason justifies an implementation here |
| Hyperdrive lifecycle | Workers Bindings managed MCP | Workers Bindings unless a local operator or Toolkit-development reason justifies an implementation here |
| R2 bucket lifecycle | Workers Bindings managed MCP or API MCP | Official managed surface unless a separate local reason exists |
| R2 bounded object reads/writes | `cloudflare-mcp` R2 tools | `cloudflare-mcp` when local object policy/readback matters |
| Worker script upload with digest evidence | `workers_upload_script` | `cloudflare-mcp` |
| Worker settings/bindings readback | `get_worker_settings`, `patch_worker_settings`, binding tools | `cloudflare-mcp` when part of guarded deployment; otherwise Workers Bindings MCP |
| Workers Builds/build logs | Workers Builds managed MCP | Managed MCP |
| Workers Observability events | Observability managed MCP or local `workers_observability_*` | Choose based on surrounding trust/session or conformance needs |
| Browser rendering/screenshots | Browser Run managed MCP | Managed MCP |
| Billing/usage spike attribution | `account_billing_usage`, then `graphql_analytics_query` | Local when part of operator investigation; managed GraphQL for broader exploration |
| WAF investigation | Local WAF summaries or managed GraphQL/API | Local tools when compact operator evidence is desired |
| WAF mutation planning/apply | `waf_ruleset_plan_change` | `waf_ruleset_apply_change` |
| Audit logs | Audit Logs managed MCP | Managed MCP |
| Logpush health | Logpush managed MCP | Managed MCP |
| DNS performance analytics | DNS Analytics managed MCP | Managed MCP |
| Radar internet trends | Radar managed MCP | Managed MCP |
| AI Gateway logs | AI Gateway managed MCP | Managed MCP |
| AutoRAG search/query | AutoRAG managed MCP | Managed MCP |
| DEX/CASB investigation | Matching managed MCP | Managed MCP |
| Sandbox development environment | Container managed MCP | Managed MCP |
| Cache/Bulk Redirect/Email Routing mutation | Local curated tool when present | `cloudflare-mcp` |
| Generic REST mutation with no curated owner | `api_prepare_call` dry-run | guarded `api_mutate`, unless the operation is denied or should be curated first |

## Code Mode versus local `api_*`

Do not treat these as interchangeable implementations of the same tool.

Cloudflare Code Mode:

```text
agent-generated JavaScript searches current spec
        ↓
agent-generated JavaScript executes in isolated Worker
        ↓
cloudflare.request() calls provider API
```

Local API parity:

```text
search committed operation catalog
        ↓
select exact known operation
        ↓
server constructs request
        ↓
local deny/read-only/confirmation/approval policy
        ↓
provider API
```

Prefer Code Mode when freshness and breadth dominate. Prefer the local route when
local admission and credential placement are part of the requirement.

Cloudflare also supports `?codemode=false` on the official API MCP, which
registers individual endpoint tools rather than the Code Mode trio. That can be
useful for clients that already have their own code-execution layer, but it does
not add this repository's local operator policy by itself.

## Managed MCP Profile Set

Use the checked-in profile template to place selected official Cloudflare MCPs
beside this server. Enable only the endpoints needed for the current operator
lane:

| Profile key | Managed endpoint | Prefer for |
| --- | --- | --- |
| `cloudflare-api` | `https://mcp.cloudflare.com/mcp` | Broad current Cloudflare API discovery through Code Mode `search()` and `execute()` |
| `cloudflare-docs` | `https://docs.mcp.cloudflare.com/mcp` | Current Cloudflare reference docs |
| `cloudflare-agents-docs` | `https://agents.cloudflare.com/mcp` | Agents SDK docs and MCP protocol guidance |
| `cloudflare-bindings` | `https://bindings.mcp.cloudflare.com/mcp` | Workers bindings and KV/R2 bucket/D1/Hyperdrive resource management |
| `cloudflare-builds` | `https://builds.mcp.cloudflare.com/mcp` | Workers Builds insight and logs |
| `cloudflare-observability` | `https://observability.mcp.cloudflare.com/mcp` | Workers logs and analytics exploration |
| `cloudflare-containers` | `https://containers.mcp.cloudflare.com/mcp` | Sandbox development environments |
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
| `cloudflare-blog` | `https://blog.mcp.cloudflare.com/mcp` | Public Cloudflare Blog search/read |

The official repository also contains demonstration/example surfaces. Do not add
them to a normal operator profile merely for completeness.

## Auth and credential expectations

Cloudflare's managed account/API MCPs use Streamable HTTP at `/mcp`. Interactive
clients typically authorize with OAuth; automation can attach an appropriate
Cloudflare bearer token where the service supports it. Grant only the
permissions required by the selected managed endpoint and workflow.

The local server's Cloudflare credential is a separate trust boundary. Do not
assume that enabling the same account in both places means the credential is
shared or that local read-only/approval policy constrains calls made through an
official managed MCP.

Historical unauthenticated smoke observations from 2026-06-20 were:

- `https://docs.mcp.cloudflare.com/mcp`: initialized without account auth;
- `https://mcp.cloudflare.com/mcp`: returned `401 invalid_token`;
- `https://graphql.mcp.cloudflare.com/mcp`: returned `401 invalid_token`;
- `https://auditlogs.mcp.cloudflare.com/mcp`: returned `401 invalid_token`.

Those observations are retained as historical operational evidence, not claimed
as a fresh 2026-08-25 availability test. Managed authorization behaviour may
change.

## Guardrails

Do not replace a curated tool with generic `api_mutate` only because the REST
endpoint exists. Curated tools are allowed to be narrower than the full API when
they provide safer planning, policy checks, readback, audit fields, or deliberate
Toolkit conformance coverage.

Do not force every Cloudflare API endpoint into this repository. Generic parity
belongs in the committed REST catalog and guarded executor; broad current API
exploration belongs in Cloudflare's managed Code Mode server.

Do not use official managed MCPs as the final apply path for a workflow whose
requirement is specifically this server's approval gate, confirmation token,
policy invariant, local artifact identity, or post-apply readback. Use official
MCPs to discover the endpoint or schema, then encode the production-affecting
workflow here when it needs durable guarded operation.

Do not imply the inverse either: if the official product MCP already provides
the needed capability and there is no local operator or Toolkit-development
reason, prefer it over adding a redundant curated tool here.

When choosing a path, record enough evidence for the next agent:

- MCP server and tool used;
- source commit or managed server URL;
- dry-run output and confirmation/approval identity for local mutations;
- readback result for mutations;
- release provenance manifest or binary hash when relying on a local installed
  binary;
- whether current endpoint/schema discovery came from the managed service or the
  committed local catalog;
- when a local overlap exists primarily for Toolkit work, the reusable behavior
  being exercised and the corresponding Toolkit change when available.
