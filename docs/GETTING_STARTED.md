# Getting Started

This guide gets `cloudflare-mcp` running locally with either stdio or
Streamable HTTP.

## Prerequisites

- Rust toolchain compatible with the crate edition.
- A Cloudflare API token with the least privilege required for your workflow.

This repository pins the public Rust MCP Toolkit repository as a git
dependency, so no sibling workspace checkout is required for normal use.

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

## Run Over Stdio

Use stdio when the MCP client launches the server process directly:

```bash
CLOUDFLARE_MCP_AUTH_MODE=off \
CLOUDFLARE_MCP_API_TOKEN=<cloudflare_api_token> \
CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID=<account_id> \
CLOUDFLARE_MCP_DEFAULT_ZONE_ID=<zone_id> \
cargo run -- --stdio
```

Stdio mode does not expose `/health`, `/attest`, or OAuth discovery routes.
Logs and diagnostics are written to stderr so stdout remains MCP JSON-RPC.

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

Keep Cloudflare upstream API credentials separate from MCP bearer auth. MCP
auth controls who may call this server; Cloudflare API credentials control what
the server may do upstream.

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

See [SECURITY_MODEL.md](SECURITY_MODEL.md) for details.

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

For docs-only changes, link checks and public wording scans are usually enough.
For behavior or tool-surface changes, run:

```bash
cargo fmt --check
cargo test
cargo test --test mcp_stdio_smoke
CLOUDFLARE_MCP_AUTH_MODE=off cargo run -- --print-tools
```
