# Getting Started

This guide gets `cloudflare-mcp` running locally with either stdio or Streamable
HTTP and explains when to compose it with Cloudflare's official managed MCPs.

## Choose the topology first

There are three sensible starting shapes.

### Local operator server only

Use only `cloudflare-mcp` when the session primarily needs this repository's
curated workflows, local artifact access, local credential custody, or a strict
read-only/approval-gated operator profile.

### Local operator server plus official MCPs

This is the recommended general-purpose agent setup. Keep this server as the
guarded local mutation path and add only the official Cloudflare MCPs needed for
the current task:

- Code Mode API MCP for broad/current endpoint discovery;
- Docs MCP for current Cloudflare documentation;
- product MCPs for services such as Workers Builds, Observability, Browser Run,
  Radar, Audit Logs, DNS Analytics, AI Gateway, AutoRAG, and other specialist
  surfaces.

Start from
[`../packaging/codex/cloudflare-managed-mcp.example.toml`](../packaging/codex/cloudflare-managed-mcp.example.toml).
Do not enable every managed endpoint by default; each additional service can add
a separate authorization surface and tool inventory.

### Official Cloudflare MCPs only

Use the official hosted services when broad current API reach or a managed
product-specific surface is all that is required and there is no need for this
repository's local policy, local files, confirmation-bound apply path, or
post-apply verification contract.

See [OFFICIAL_MCP_COMPARISON.md](OFFICIAL_MCP_COMPARISON.md) for the detailed
tradeoffs and [AGENT_ROUTING.md](AGENT_ROUTING.md) for task-level decisions.

## Prerequisites

- Rust toolchain compatible with the crate edition.
- A Cloudflare API token with the least privilege required for your workflow,
  or a configured upstream Cloudflare OAuth client.

This repository pins the public Rust MCP Toolkit repository as a git dependency,
so no sibling workspace checkout is required for normal use.

```bash
cargo build
```

## Credentials

At minimum, most Cloudflare calls need:

```bash
export CLOUDFLARE_MCP_API_TOKEN=<cloudflare_api_token>
export CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID=<account_id>
export CLOUDFLARE_MCP_DEFAULT_ZONE_ID=<zone_id>
```

The account and zone can also be supplied per tool call. Defaults are a
convenience for operator sessions, not a replacement for least-privilege
Cloudflare tokens.

R2 object tools use S3-compatible R2 credentials:

```bash
export CLOUDFLARE_MCP_R2_ACCESS_KEY_ID=<r2_access_key_id>
export CLOUDFLARE_MCP_R2_SECRET_ACCESS_KEY=<r2_secret_access_key>
```

For deployments, prefer secret files outside the repository when supported by
the corresponding `*_FILE` settings.

When you also connect Cloudflare's managed MCPs, treat their OAuth or bearer
token as a separate authorization path. A credential used by the local server
is not implicitly shared with a managed MCP endpoint and vice versa.

## Run Over Stdio

Use stdio when the MCP client launches the server process directly:

```bash
CLOUDFLARE_MCP_AUTH_MODE=off \
CLOUDFLARE_MCP_API_TOKEN=<cloudflare_api_token> \
CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID=<account_id> \
CLOUDFLARE_MCP_DEFAULT_ZONE_ID=<zone_id> \
cargo run -- --stdio
```

Stdio mode does not expose `/health`, `/attest`, or OAuth discovery routes. Logs
and diagnostics are written to stderr so stdout remains MCP JSON-RPC.

Stdio is the simplest way to keep the MCP runtime and upstream Cloudflare
credential on the same trusted host as the agent's local project files.

## Run Over Loopback HTTP

Use loopback HTTP when a local MCP client connects to a long-running server:

```bash
CLOUDFLARE_MCP_AUTH_MODE=off \
CLOUDFLARE_MCP_BIND_ADDR=127.0.0.1:9501 \
CLOUDFLARE_MCP_API_TOKEN=<cloudflare_api_token> \
CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID=<account_id> \
CLOUDFLARE_MCP_DEFAULT_ZONE_ID=<zone_id> \
cargo run
```

Smoke checks:

```bash
curl -s http://127.0.0.1:9501/health | jq .
curl -s http://127.0.0.1:9501/attest | jq .
```

Print tool names without keeping a server loop alive:

```bash
CLOUDFLARE_MCP_AUTH_MODE=off cargo run -- --print-tools
```

## Auth Profiles

For local smoke testing on loopback, `CLOUDFLARE_MCP_AUTH_MODE=off` is the
smallest configuration.

For non-loopback HTTP, auth must be enabled. The main modes are:

- `resource_server`: OAuth resource-server mode for interactive MCP clients.
- `jwks`: bearer validation with configured issuer/JWKS metadata.
- `introspection`: bearer validation through a configured introspection
  endpoint.
- `delegation`: HMAC delegated-token mode for automation that already mints
  service tokens.

Keep Cloudflare upstream API credentials separate from MCP bearer auth. MCP auth
controls who may call this server; Cloudflare API credentials control what the
server may do upstream.

That separation is one of the important differences from using a hosted managed
MCP directly: with this server, the operator owns both the inbound MCP boundary
and the upstream credential-storage boundary.

## Useful Safety Profiles

Read-only mode:

```bash
export CLOUDFLARE_MCP_READ_ONLY=1
```

Curated-tools-only mode:

```bash
export CLOUDFLARE_MCP_API_PARITY_ENABLED=0
```

Approval-gated apply mode:

```bash
export CLOUDFLARE_MCP_ELICITATION_ENABLED=1
export CLOUDFLARE_MCP_ELICITATION_APPLY_ONLY=1
```

A useful split session is to leave the official Docs/API MCPs available for
read/discovery while running this server with `CLOUDFLARE_MCP_READ_ONLY=1` until
the operator intentionally moves into a mutation lane.

See [SECURITY_MODEL.md](SECURITY_MODEL.md) for details.

## Routing a typical production change

For a production-affecting operation, use a sequence like:

```text
1. Discover current Cloudflare behaviour/docs with official managed MCPs as needed.
2. Select a curated local tool when one owns the workflow.
3. Read current state and run the local dry-run/plan path.
4. Review the resulting target, diff/digest, and confirmation requirements.
5. Apply the approved change.
6. Read back the resulting Cloudflare state.
```

Do not use a generic API route merely because it can reach the same endpoint if
a curated tool deliberately owns the safer lifecycle.

## Minimal MCP HTTP Flow

Initialize:

```bash
curl -i -X POST http://127.0.0.1:9501/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"initialize",
    "params":{
      "protocolVersion":"2024-11-05",
      "capabilities":{},
      "clientInfo":{"name":"example-client","version":"0.1.0"}
    }
  }'
```

Use the returned `Mcp-Session-Id` for later stateful calls:

```bash
curl -i -X POST http://127.0.0.1:9501/mcp \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Session-Id: <session-id>' \
  -d '{
    "jsonrpc":"2.0",
    "id":2,
    "method":"tools/call",
    "params":{"name":"health","arguments":{}}
  }'
```

For exact client requirements, see [CLIENT-CONTRACT.md](CLIENT-CONTRACT.md).

## Validation

For documentation-only changes, validate documentation structure and references
rather than manufacturing unrelated runtime test evidence. For behavior or
tool-surface changes, run:

```bash
cargo fmt --check
cargo test
cargo test --test mcp_stdio_smoke
CLOUDFLARE_MCP_AUTH_MODE=off cargo run -- --print-tools
```
