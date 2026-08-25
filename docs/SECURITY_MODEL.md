# Security Model

`cloudflare-mcp` assumes Cloudflare operations can affect production traffic,
data, and access boundaries. The server therefore keeps important safety
controls in code paths that agents must use, not only in operator prose.

## Trust Boundaries

There are two separate credential boundaries:

- MCP bearer auth controls who can call this MCP server.
- Cloudflare upstream credentials control what this server can do in Cloudflare.

Do not pass an MCP bearer token through to Cloudflare as an API token. Use
server-held Cloudflare credentials, request-header Cloudflare credentials, or the
explicit mixed mode documented in [CLIENT-CONTRACT.md](CLIENT-CONTRACT.md).

Cloudflare provider permissions remain authoritative for what the upstream API
will accept. Local MCP policy can further restrict those permissions but cannot
safely widen them.

## Self-hosted versus managed Cloudflare MCP trust placement

Cloudflare's official MCPs are managed services. When an operator authorizes one
of those endpoints, Cloudflare hosts the MCP runtime and receives the bearer
credential or OAuth authorization required by that service. This is usually the
best fit for broad current API discovery and Cloudflare-maintained product
surfaces.

With this repository, the operator owns the MCP runtime. That changes where
several security decisions live:

- inbound MCP authentication can be controlled independently of the Cloudflare
  provider credential;
- Cloudflare API tokens, OAuth refresh grants, R2 credentials, and optional
  service credentials can remain on operator infrastructure;
- the server can be bound to loopback and launched through stdio with no network
  listener at all;
- a local read-only profile can hide and deny mutation even when the upstream
  Cloudflare credential itself has write permission;
- dangerous workflows can require local confirmation identity and MCP
  elicitation before the request is sent to Cloudflare.

This is not an assertion that self-hosting is inherently safer. Self-hosting
also makes the operator responsible for patching, process isolation, secret
storage, filesystem access, reverse-proxy configuration, and deployment
hardening.

Cloudflare's official Code Mode API MCP also has a different execution boundary:
its `search` and `execute` tools run agent-generated JavaScript inside
Cloudflare's isolated Worker-based Code Mode environment. This repository's
generic `api_*` executor does not accept generated code. It selects a known
operation from a committed catalog and constructs the HTTP request itself.
That narrower execution model is intentional for operator workflows that need a
locally reviewable admission boundary.

See [OFFICIAL_MCP_COMPARISON.md](OFFICIAL_MCP_COMPARISON.md) for the broader
capability comparison.

## Local artifact boundary

Some curated tools intentionally access local files or directories, including
Pages direct-upload artifacts, Worker bundles/scripts, and migration material.
That is a capability the hosted official MCPs do not have against an arbitrary
caller filesystem.

Treat local file access as part of the trust model:

- run the server under a principal with only the filesystem access it needs;
- do not expose the server to untrusted MCP callers merely because upstream
  Cloudflare credentials are narrow;
- prefer bounded, explicit artifact paths rather than treating the MCP process
  as a general filesystem service;
- keep secret files outside deployable source trees and use dedicated `*_FILE`
  settings where supported.

## Bind and Host Safety

The default bind address is loopback. Non-loopback bind requires auth enabled
and explicit HTTPS values for `CLOUDFLARE_MCP_AUTH_RESOURCE_URL` and
`CLOUDFLARE_MCP_AUTH_AUDIENCE`. Loopback development may continue to use local
HTTP URLs or derive its audience from the local resource URL.

The server also checks the HTTP `Host` header against
`CLOUDFLARE_MCP_ALLOWED_HOSTS`. This reduces accidental exposure through
unexpected reverse proxy or DNS paths.

## Strict Tool Inventory

The runtime owns a strict registered tool inventory:

- Unknown tools are denied.
- Read-only mode filters mutating tools from `tools/list`.
- Direct calls to filtered mutating tools are denied.
- Feature-gated generic API parity tools can be hidden and denied.

This keeps the visible and callable MCP surface aligned with server policy.

## Read-Only Mode

Set:

```bash
export CLOUDFLARE_MCP_READ_ONLY=1
```

Expected behavior:

- `tools/list` exposes only read-only tools.
- Mutating tools are not callable.
- `health` and `/health` report `read_only_mode=true`.

Use this for audit, discovery, and investigation sessions where mutation should
be impossible from this MCP even if the configured Cloudflare credential could
write upstream.

## Dry-Run and Apply

Mutating tools should be called with `dry_run=true` before live apply.

Dry-run responses are deterministic plans: they describe intended requests,
targets, policy decisions, and audit metadata without Cloudflare side effects.
High-risk operations may require confirmation tokens from dry-run output before
apply.

Recommended headers for mutating calls:

- `x-correlation-id`: stable operation correlation key.
- `x-request-id`: per-request trace key.

These values are reflected in mutation audit metadata.

## Elicitation Approval Gates

When enabled, the server can issue MCP `elicitation/create` requests before
configured dangerous tool calls:

```bash
export CLOUDFLARE_MCP_ELICITATION_ENABLED=1
export CLOUDFLARE_MCP_ELICITATION_APPLY_ONLY=1
```

Behavior:

- Apply calls for configured dangerous tools require explicit approval.
- Dry-run calls bypass approval by default when apply-only mode is enabled.
- Unsupported clients fail closed by default.
- Approval prompts include a stable request digest and bounded argument preview.
- Approval responses must echo the request digest to prevent approving a
  different request by accident.

This pattern is intended to become a reusable MCP Toolkit safety primitive.
Cloudflare-specific dangerous-tool defaults remain local to this server.

## Generic API Parity Guardrails

The `api_*` tools provide broad Cloudflare REST API v4 access through a
committed OpenAPI-derived catalog.

`api_mutate` is guarded:

- Dry-run is expected before apply.
- Apply requires the dry-run confirmation token.
- Denied-by-default risk categories fail closed.
- Read-only mode denies mutation.
- Elicitation can be mandatory for generic mutations.
- Curated workflows can reserve an operation so the generic executor cannot be
  used to bypass the stronger lifecycle.

Use curated tools first when `api_get_operation` reports a preferred tool.

These controls are the principal security difference between this repository's
generic executor and a broad managed API-access MCP: the final admission policy
is part of the local runtime rather than being left entirely to agent-generated
call logic and provider permissions.

## External Service Bridge

The optional allowlisted external service bridge lets deployments call approved
operator endpoints while keeping service credentials on the server side.

Security properties:

- URLs must match configured HTTPS allowlist prefixes.
- Secrets are attached internally and not returned in tool output.
- Dry-run is supported.
- Output is sanitized and bounded.

Deployments should choose their own allowlist and credential names. Public docs
use placeholders rather than organization-specific endpoints.

## Secret Handling

Do not commit:

- Cloudflare API tokens.
- OAuth client secrets.
- R2 access keys.
- Access service token secrets.
- External service bridge credentials.

Prefer environment variables or protected files outside the repository. On Unix
systems, secret files should be regular owner-only files.

## Hosted Upstream OAuth

Inbound MCP authorization and Cloudflare provider authorization are separate
trust boundaries. The hosted provider flow uses authorization code + PKCE and a
narrow public callback. The callback remains behind the Host allowlist and
returns only generic success or failure HTML.

Pending transactions are bounded, expire, are replaced per authenticated
principal, are indexed by a digest of state, and are removed before code
exchange. They are process-local; horizontally scaled deployments must keep a
transaction on one instance or provide encrypted shared coordination.

Refresh grants are persisted through the toolkit's provider-neutral storage
boundary. The bundled single-host store rejects unsafe file types, symlinked
paths, and non-owner-only token files on Unix. Deployments that require
encryption at rest should replace that storage boundary with their platform
secret service. Cache filenames use one-way principal keys, and provider state
and cached access tokens are isolated per authenticated MCP actor. Access
tokens, refresh tokens, client secrets, authorization codes, and raw state are
excluded from tool status and formatted debug output.

## Validation Expectations

For behavior changes affecting safety controls, run:

```bash
cargo fmt --check
cargo test
cargo test --test mcp_stdio_smoke
CLOUDFLARE_MCP_AUTH_MODE=off cargo run -- --print-tools
```

For tool schema changes, also update and re-check the schema snapshot as
described in [../spec/README.md](../spec/README.md).

For documentation-only changes, validate documentation structure and exact
changed blobs. Do not run unrelated runtime tests solely to manufacture green
CI evidence for prose-only edits.
