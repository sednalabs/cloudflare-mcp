# Client compatibility

`cloudflare-mcp` is an MCP server, not a model-specific integration. Public
setup guidance should therefore describe the client capabilities a workflow
needs rather than recommend a particular model version.

## Core MCP capabilities

A client can use the server over either:

- local stdio, where the client launches `cloudflare-mcp --stdio`; or
- MCP Streamable HTTP at `/mcp`.

For ordinary tool use, the client needs normal MCP initialization, tool listing,
and tool-call support. Stateful HTTP clients must preserve the returned MCP
session identifier where required by the configured transport mode.

## Large tool catalogs

The server intentionally exposes a substantial curated tool inventory. Clients
can handle that in several ways:

- use the client's native/deferred MCP tool loading or tool-search capability;
- call the local `find_tools` helper and use its narrowed result for a follow-up
  request;
- run the server in curated-only or read-only profiles when the workflow needs a
  smaller surface for policy reasons.

For OpenAI Responses API clients that support MCP deferred loading and tool
search, configure the MCP server with `defer_loading: true` and include a
`tool_search` tool. Model and product availability changes over time, so consult
current OpenAI product documentation for which models expose those client-side
features rather than treating a model name in this repository as a
recommendation.

The resource `cloudflare-mcp://openai/tool-search-config` exposes the server's
current MCP/tool-search template and optional reviewed read-only approval
override.

## Approval and elicitation

There are two distinct approval surfaces:

1. client-side approval before a remote MCP tool receives request data; and
2. optional server-side MCP elicitation before configured dangerous apply
   operations execute.

Do not assume one automatically replaces the other. A client that connects to a
server with elicitation enabled must support the required MCP elicitation flow,
or the server will fail closed unless the deployment has explicitly chosen a
different policy.

For OpenAI clients, leave remote-MCP approval at its safe default unless the
server and workflow have been reviewed. If approval is relaxed, keep the
exception narrow and read-only; do not make a model/version choice part of the
security decision.

## Authentication compatibility

Inbound MCP authentication and upstream Cloudflare credentials are separate.
A compatible remote client must be able to present the bearer authorization
expected by the configured MCP auth profile. Cloudflare OAuth or API-token
selection then happens at the server's upstream boundary.

For local stdio, MCP bearer auth can be disabled because there is no network MCP
listener. The Cloudflare credential still controls what the process can do
upstream.

See [CLIENT-CONTRACT.md](CLIENT-CONTRACT.md) for exact transport and auth
requirements and [SECURITY_MODEL.md](SECURITY_MODEL.md) for the trust model.

## Documentation rule

When adding client examples to this repository:

- state the required MCP/client capability;
- show configuration shapes using placeholders;
- avoid saying a particular model is the current, preferred, or flagship model;
- link to the vendor's current documentation when model availability is
  material;
- keep server-side safety behavior independent of model branding.

This keeps the repository accurate even as hosted client products and model
names change independently of the MCP server.
