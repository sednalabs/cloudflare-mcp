# Cloudflare MCP comparison

This document explains the practical difference between
`sednalabs/cloudflare-mcp` and Cloudflare's official MCP services. It is not a
ranking. The services make different trade-offs around hosting, API freshness,
local policy, and workflow design, and they can be used together.

## Snapshot used for this comparison

This comparison was refreshed on 2026-08-25 against these immutable upstream
generations:

- `cloudflare/mcp` at
  `75c4dbc005e2ee14b937b18089a7880062264351`;
- `cloudflare/mcp-server-cloudflare` at
  `08d743654176c7e79921a5d596d17678ec900f39`.

Cloudflare's managed services can evolve independently of those repository
commits. Treat this document as a repository-grounded comparison, not a promise
that every hosted endpoint will retain the same tool inventory. For current
product discovery, prefer Cloudflare's managed Docs and API MCPs.

## Three different MCP shapes

### This project: self-hosted operator server

`cloudflare-mcp` runs as a Rust process under the operator's control. It exposes
an explicit inventory of curated tools and a smaller generic `api_*` fallback
for the Cloudflare REST API.

The main difference is that important operational policy can live in the MCP
runtime itself:

- read-only mode changes both discovery and dispatch;
- mutation tools can require a deterministic dry-run first;
- confirmation tokens bind approval to a particular plan;
- MCP elicitation can require an explicit human approval step;
- dangerous generic API categories can fail closed;
- curated workflows can own a lifecycle and block the generic escape hatch;
- readback is part of many mutation contracts;
- local files can participate in deploy/migration workflows because the server
  can run beside the working tree.

### Cloudflare: Code Mode API MCP

Cloudflare's general API MCP at `https://mcp.cloudflare.com/mcp` optimizes for
very broad API reach without injecting thousands of endpoint schemas into the
model context.

In Code Mode the visible surface is intentionally small:

- `docs` searches Cloudflare developer documentation;
- `search` executes agent-generated JavaScript against the API specification;
- `execute` executes agent-generated JavaScript that can call
  `cloudflare.request()`.

The upstream project advertises roughly 2,500 API endpoints behind this small
surface. The generated JavaScript runs in Cloudflare's isolated Worker-based
Code Mode environment. This gives the agent a flexible API programming model
without exposing the full OpenAPI schema as MCP tool definitions.

Code Mode can be disabled with `?codemode=false`. In that mode the official
server registers individual endpoint tools instead. That can be useful for
clients that cannot or should not compose multiple code-execution systems, but
it has a much larger tool-schema context cost.

### Cloudflare: domain-specific managed MCPs

Cloudflare also operates separate hosted MCPs with purpose-built tools for
specific domains. The current official repository includes services for areas
such as:

- developer documentation;
- Workers Bindings;
- Workers Builds;
- Workers Observability;
- sandbox containers;
- Browser Run;
- Logpush;
- AI Gateway;
- AutoRAG;
- Audit Logs;
- DNS Analytics;
- Digital Experience Monitoring;
- Cloudflare One CASB;
- Radar;
- Cloudflare Blog;
- other product-specific or demonstration surfaces.

These servers are often the best interface when the desired operation already
maps cleanly to the curated product domain.

## Tangible architectural differences

| Dimension | `sednalabs/cloudflare-mcp` | Official Code Mode API MCP | Official domain MCPs |
| --- | --- | --- | --- |
| Hosting | Operator-controlled process | Cloudflare managed service | Cloudflare managed service |
| Main optimization | Governed production operations | Broad current API reach with small context | Product-specific usability |
| Generic execution | Catalog-selected HTTP operations | Agent-generated JavaScript | Usually typed product tools |
| API source | Committed OpenAPI-derived catalog | Cloudflare's current hosted API/spec implementation | Product implementation |
| Update cadence | Explicit repository/catalog refresh | Cloudflare-managed | Cloudflare-managed |
| Runtime policy before mutation | Central design concern | Caller logic plus Cloudflare authorization | Product-specific |
| Dry-run plan identity | First-class on many write paths | Not a general API-MCP contract | Tool-specific |
| Confirmation token | Supported/required on guarded paths | Not a general API-MCP contract | Tool-specific |
| Human MCP elicitation | Supported for configured apply paths | Not a general API-MCP contract | Server-specific |
| Post-apply readback | Part of many curated operations | Agent may issue follow-up reads | Tool-specific |
| High-risk generic deny list | Yes | API permissions determine provider reach | Server-specific |
| Global read-only mode | Yes | No equivalent operator-wide mode | Server-specific |
| Local filesystem/artifact access | Yes when deployed locally | No direct caller-filesystem access | No direct caller-filesystem access |
| Upstream credential custody | Can remain on operator infrastructure | Cloudflare managed MCP receives authorization/token | Cloudflare managed MCP receives authorization/token |
| Inbound MCP auth boundary | Independently controlled by operator | Managed by Cloudflare service | Managed by Cloudflare service |

## Why the generic API fallbacks are not equivalent

Both `cloudflare-mcp` and Cloudflare's Code Mode MCP can reach a very broad set
of Cloudflare APIs, but they do so differently.

The local generic path is:

```text
api_find_operations
        ↓
api_get_operation / api_prepare_call
        ↓
api_read OR guarded api_mutate dry-run
        ↓
confirmation / approval where required
        ↓
api_mutate apply
```

The selected operation must already exist in the committed catalog. The server
constructs the HTTP request. Generic mutation policy is applied before provider
access, and some operations are denied from this route entirely.

The Cloudflare Code Mode path is conceptually:

```text
agent writes search JavaScript
        ↓
search executes against current spec
        ↓
agent writes execution JavaScript
        ↓
execute runs code in an isolated Worker
        ↓
cloudflare.request() calls the API
```

That is flexible and context-efficient for discovery and broad API use. It is
also intentionally a more general execution primitive. If an organization
needs a mandatory local admission policy before a production mutation, that
policy has to live somewhere else or be encoded in a narrower server/tooling
layer.

## Workflow differences that matter in practice

### D1

Cloudflare's Workers Bindings MCP offers direct D1 resource operations such as
list, create, get, delete, and query. The broad Code Mode API MCP can reach the
underlying D1 APIs as well.

This repository adds an operator workflow around D1:

- separate read-only SQL classification and validation;
- row-write-only mutation tooling for ordinary data changes;
- exact-byte migration manifests;
- plan digests and target-state checks;
- bootstrap migration-ledger custody;
- migration leases;
- reconciliation evidence;
- explicit finalize/abort paths;
- generic raw query/import/time-travel restore restrictions where they would
  cross the curated safety boundary.

Use the official MCP when direct current API access is the goal. Use the local
D1 tools when the lifecycle and evidence around the change are part of the
requirement.

### DNS, Access, and publication

The official API MCP can manipulate the relevant DNS and Access endpoints.
`cloudflare-mcp` additionally defines a publication sequence:

- inspect Access applications and policies;
- verify the hostname gate;
- evaluate publish preflight;
- perform the DNS mutation through a guarded publish path;
- verify observed DNS state and, where appropriate, HTTP/Access behavior;
- provide a narrow idempotent emergency-unpublish operation.

The point is not endpoint coverage. It is preventing an agent from treating
"create the DNS record" as the whole production publication transaction.

### WAF

The official API MCP can call Rulesets and GraphQL APIs directly. This
repository also provides a higher-level WAF lifecycle:

- summarize current Rulesets;
- summarize Security Events;
- correlate a rule with recent activity;
- construct a stable typed edit plan;
- check rule caps and stale/list conditions;
- issue a confirmation token;
- apply the approved edit;
- read the Ruleset back and optionally include current Security Events context.

### Workers deployment

Cloudflare's API MCP can ultimately invoke Worker deployment APIs. This
repository deliberately blocks generic Worker-script content upload and routes
that operation through `workers_upload_script` instead.

The curated upload path can bind the deployable bytes to a digest, emit a
stable dry-run summary, require the confirmation associated with that exact
artifact, then read settings back after upload.

### Pages and local artifacts

`pages_deploy_directory` can inspect and upload a local output directory because
the self-hosted MCP can run next to the build tree. The hosted official MCP
cannot directly open arbitrary files from the caller's filesystem.

This is a meaningful operational distinction for generated Pages output,
prebuilt Worker bundles, local migration files, and other artifacts whose exact
bytes matter.

## Areas where the official MCP family is the better fit

Do not add a local curated tool merely to mirror every Cloudflare product.
Prefer the official managed MCP when its product-specific capability already
fits the task and no stronger local admission/readback contract is needed.

Examples include:

- KV namespace management;
- Hyperdrive configuration management;
- Workers Builds details and build logs;
- Browser rendering, markdown extraction, and screenshots;
- Radar internet insights;
- Audit Logs reporting;
- Logpush health summaries;
- AI Gateway log exploration;
- AutoRAG search/query;
- Digital Experience Monitoring;
- Cloudflare One CASB analysis;
- sandbox container workflows;
- current Cloudflare documentation search.

The generic Code Mode API MCP is also preferred for rare or newly introduced
Cloudflare APIs that are not yet present in this repository's committed catalog
or curated tools.

## Areas with strong overlap

Workers Observability is a good example of real overlap. Cloudflare's managed
Observability MCP exposes tools for querying events and exploring keys/values.
This repository exposes comparable event/key/value discovery functions inside
the same self-hosted operator server.

Choose based on the surrounding trust and workflow requirement:

- use the managed Observability MCP for a convenient Cloudflare-hosted analysis
  surface;
- use the local tools when the same agent session already needs the guarded
  operator server or local credential boundary.

## Credential and trust placement

Both approaches still depend on Cloudflare's provider-side authorization.
Least-privilege API tokens/OAuth scopes remain mandatory regardless of MCP
choice.

With a Cloudflare managed MCP, Cloudflare hosts the MCP runtime and receives the
credential/authorization needed for the selected service.

With self-hosted `cloudflare-mcp`, inbound MCP authorization and upstream
Cloudflare authorization are distinct boundaries:

- the operator controls who may call the MCP service;
- the operator controls where Cloudflare tokens, OAuth refresh grants, R2 keys,
  and service credentials are stored;
- the process can be bound only to loopback or placed behind the operator's own
  resource-server/JWKS/introspection/delegation boundary;
- a read-only profile can remove mutation capability even when the upstream
  Cloudflare credential itself would permit writes.

That is useful when the local execution environment is part of the security
model. It also means the operator is responsible for hardening and updating the
self-hosted process.

## Using the servers together

For many workflows, a practical default is not to pick exactly one Cloudflare
MCP. Use the surfaces together when their responsibilities differ:

```text
Cloudflare Docs MCP
        ↓
current documentation

Cloudflare Code Mode API MCP
        ↓
broad/current endpoint discovery

product-specific official MCPs
        ↓
specialist managed workflows

sednalabs/cloudflare-mcp
        ↓
local workflow where additional policy or readback is required
```

Practical examples:

| Task | Preferred start | Preferred final mutation path |
| --- | --- | --- |
| Find a newly released Cloudflare endpoint | Official Code Mode API MCP | Code Mode unless a guarded lifecycle is required |
| Read current Cloudflare docs | Official Docs MCP | N/A |
| Inspect Worker build logs | Official Workers Builds MCP | N/A or matching product tool |
| Browser-render a page | Official Browser Run MCP | N/A |
| Deploy a known local Worker artifact with approval evidence | Local curated Worker tools | `cloudflare-mcp` |
| Publish a hostname behind Access | Local publish/Access tools | `cloudflare-mcp` |
| Change a WAF Ruleset under explicit plan approval | Local WAF plan/apply tools | `cloudflare-mcp` |
| Run a one-off low-risk API call with no curated workflow | Official Code Mode or local `api_*` | Choose based on credential and policy needs |
| Use an API absent from the local catalog | Official Code Mode API MCP | Official, or refresh/curate locally before governed production use |

See [AGENT_ROUTING.md](AGENT_ROUTING.md) for the operational routing rules,
[PROJECT_SCOPE.md](PROJECT_SCOPE.md) for project scope and contribution
guidance, and
[../packaging/codex/cloudflare-managed-mcp.example.toml](../packaging/codex/cloudflare-managed-mcp.example.toml)
for a profile that enables selected official MCPs beside the local server.

## Non-goals

This repository does not claim that:

- Cloudflare's official MCPs are unsafe;
- every mutation must pass through this server;
- a confirmation token substitutes for Cloudflare least privilege;
- a self-hosted service is inherently more secure than a managed service;
- the committed API catalog is always as fresh as Cloudflare's hosted MCP;
- every official product MCP should be reimplemented locally.

The narrower point is that some production operations need more than raw
endpoint reach. Where deterministic planning, local policy, approval identity,
artifact identity, and readback are requirements, this repository provides a
place to enforce them.
