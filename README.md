# cloudflare-mcp

`cloudflare-mcp` is a self-hosted Model Context Protocol server for
safety-sensitive Cloudflare operations. It gives agents and operator tools a
structured way to inspect Cloudflare state, plan changes, require approval for
dangerous apply calls, and verify readback after mutations.

It is built as a reference implementation of the Rust MCP Toolkit: explicit
tool inventory, Streamable HTTP and stdio transports, OAuth-aware auth surfaces,
schema snapshot tests, guarded mutation plans, and optional human approval
gates.

## What it does

The server focuses on operational workflows where correctness and auditability
matter more than raw endpoint breadth:

- Cloudflare Tunnel, DNS, and Access publish workflows.
- Pages deployments and custom domains.
- D1 database discovery, read-only queries, guarded writes, and migrations.
- R2 object inspection, bounded reads/downloads, and writes.
- Workers script upload with digest-based summaries and settings readback,
  bindings discovery, and observability event queries.
- Queues health, backlog, metrics, consumers, and DLQ readback.
- Account billing usage and Cloudflare Analytics GraphQL attribution for
  usage-spike investigations.
- WAF Rulesets and Security Events summaries for rule/activity investigations.
- Cache controls, Bulk Redirects, Email Routing, and account API token
  management.
- A guarded generic Cloudflare REST API v4 executor backed by a committed
  OpenAPI-derived catalog.

Mutating tools are designed around dry-run planning, optional confirmation
tokens, structured audit metadata, digest-based evidence for deployable
artifacts, and readback verification.

## Relationship to Cloudflare's official MCP server

Cloudflare provides official managed MCP servers for broad Cloudflare API
access, current docs, GraphQL analytics, observability, browser rendering, and
other product-specific workflows. If you want general-purpose access to the full
Cloudflare API with minimal model context, start with Cloudflare's Code Mode API
MCP server.

This project serves a different purpose. It is a self-hosted operator MCP
server for workflows where local credential control, curated safety policy,
dry-run/apply discipline, approval gates, and post-apply verification matter.
It complements the official server rather than replacing it.

This project is not an official Cloudflare product.

## Safety model

`cloudflare-mcp` is private by default and keeps safety controls in the runtime,
not only in documentation:

- Non-loopback bind requires MCP auth plus explicit HTTPS resource and audience
  URLs.
- Strict tool inventory denies unregistered tools.
- Read-only mode hides and denies mutating tools.
- Curated tool workflows are preserved for operations with product-specific
  safety policy.
- Mutating tools support deterministic dry-run plans.
- Dangerous apply calls can require MCP elicitation approval.
- Mutation responses include structured audit metadata with correlation IDs.
- Publish flows evaluate policy gates before DNS mutation.
- Emergency unpublish is idempotent.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the longer version.

## Quick start

### Build

```bash
cargo build
```

The server depends on the public Rust MCP Toolkit repository by pinned git
revision, so a fresh clone of this repository is enough for normal builds.

### Local stdio

Use stdio when an MCP client launches the process directly:

```bash
CLOUDFLARE_MCP_AUTH_MODE=off \
CLOUDFLARE_MCP_API_TOKEN=<cloudflare_api_token> \
CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID=<account_id> \
CLOUDFLARE_MCP_DEFAULT_ZONE_ID=<zone_id> \
cargo run -- --stdio
```

In stdio mode, MCP JSON-RPC uses stdin/stdout and logs go to stderr. Auth
defaults to `off` unless `CLOUDFLARE_MCP_AUTH_MODE` is set.

### Local loopback HTTP

Use loopback HTTP for local Streamable HTTP clients:

```bash
CLOUDFLARE_MCP_AUTH_MODE=off \
CLOUDFLARE_MCP_BIND_ADDR=127.0.0.1:9501 \
CLOUDFLARE_MCP_API_TOKEN=<cloudflare_api_token> \
CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID=<account_id> \
CLOUDFLARE_MCP_DEFAULT_ZONE_ID=<zone_id> \
cargo run
```

Smoke check:

```bash
curl -s http://127.0.0.1:9501/health | jq .
curl -s http://127.0.0.1:9501/attest | jq .
```

Print the registered tool inventory without starting the server loop:

```bash
CLOUDFLARE_MCP_AUTH_MODE=off cargo run -- --print-tools
```

### Cloudflare browser authorization

Hosted deployments can replace a long-lived configured Cloudflare API token
with Cloudflare's authorization-code flow. Register a Cloudflare OAuth client
with both `authorization_code` and `refresh_token` grants, the exact callback
URL `https://<host>/oauth/cloudflare/callback`, and only the dot-delimited API
scopes the server needs. A private client is appropriate when only members of
the owning Cloudflare account will authorize it; making the client public is
not required for a private operator service.

Cloudflare documents the registration and endpoint contracts in
[Create your OAuth client](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/)
and [Integrate your OAuth client with Cloudflare](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/).

```bash
CLOUDFLARE_MCP_UPSTREAM_OAUTH_ENABLED=1
CLOUDFLARE_MCP_UPSTREAM_OAUTH_CLIENT_ID=<client_id>
CLOUDFLARE_MCP_UPSTREAM_OAUTH_CLIENT_SECRET_FILE=/run/secrets/cloudflare-oauth-client-secret
CLOUDFLARE_MCP_UPSTREAM_OAUTH_CALLBACK_URL=https://<host>/oauth/cloudflare/callback
CLOUDFLARE_MCP_UPSTREAM_OAUTH_SCOPES=<scope.one>,<scope.two>
CLOUDFLARE_MCP_UPSTREAM_OAUTH_TOKEN_CACHE=/var/lib/cloudflare-mcp/upstream-oauth.json
```

The default Cloudflare endpoints are
`https://dash.cloudflare.com/oauth2/auth` and
`https://dash.cloudflare.com/oauth2/token`; private clients default to
`client_secret_basic`. Public PKCE clients can set
`CLOUDFLARE_MCP_UPSTREAM_OAUTH_TOKEN_AUTH_METHOD=none` and omit the secret.

For a process-launched stdio server on a remote desktop or lab host, register a
fixed loopback callback such as
`http://127.0.0.1:9502/oauth/cloudflare/callback`. The login tool opens that
listener inside the existing MCP process and completes the exchange in the
background, so a browser on the same host can authorize without a second
daemon. If the browser is elsewhere, forward the registered loopback port over
SSH before starting login. Only one process can own a fixed loopback port at a
time.

After the service starts, call `cloudflare_auth_status`, then
`cloudflare_auth_login`. Open the returned short-lived URL in a browser. The
registered callback completes the exchange and stores only the refresh grant
behind the toolkit storage boundary. Call `cloudflare_auth_probe` to verify the
grant. `cloudflare_auth_logout` requires `confirm=true` and clears local state;
it does not revoke the provider-side authorization.

`cloudflare_auth_login` reports `completion_mode=loopback_callback` for the
stdio path and `completion_mode=hosted_callback` for an HTTPS service callback.
Poll `cloudflare_auth_status` until `last_login_status=succeeded` before probing.

The configured token-cache value is a base path. The runtime appends a SHA-256
principal key to the filename, keeping grants and cached access tokens isolated
between authenticated MCP actors without exposing actor names on disk.

Credential selection is deterministic: a configured per-request header wins,
then a configured static token, then the OAuth grant. The OAuth callback is
public so Cloudflare can reach it, but remains subject to the server's Host
allowlist. Never paste callback URLs into chat or logs because they contain a
short-lived authorization code and state.

See [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) for client setup,
configuration profiles, and validation examples.

For agents that should use this guarded server beside Cloudflare's official
managed MCP endpoints, start from
[packaging/codex/cloudflare-managed-mcp.example.toml](packaging/codex/cloudflare-managed-mcp.example.toml).
It keeps the local dry-run/apply/readback path separate from managed discovery
surfaces such as Cloudflare Docs, Code Mode API, GraphQL, Observability, Audit
Logs, DNS Analytics, and Browser Run.

## MCP client usage

The server supports:

- Streamable HTTP at `POST|GET|DELETE /mcp`.
- Local stdio with `--stdio`.
- Public endpoints at `GET /health`, `GET /attest`, and the narrowly scoped
  `GET /oauth/cloudflare/callback` OAuth return route.
- MCP resources:
  - `cloudflare-mcp://about`
  - `cloudflare-mcp://help`
  - `cloudflare-mcp://adapter-status`
  - `cloudflare-mcp://api-parity-status`
  - `cloudflare-mcp://openai/tool-search-config`

Tool names intentionally omit a `cloudflare.` prefix. MCP clients already attach
the server label, so short names keep prompts and traces easier to read.

For OpenAI Responses API clients, GPT-5.4 and later support tool search; use
`gpt-5.5` as the current flagship target for complex operator workflows. To
defer this large MCP tool catalog, configure the MCP server with
`defer_loading: true` and include a `tool_search` tool. Non-hosted clients can
call `find_tools` to produce a narrow `allowed_tools` list and optional MCP
schemas before a follow-up call.

```json
[
  {
    "type": "mcp",
    "server_label": "cloudflare",
    "server_description": "Self-hosted Cloudflare operator workflows: Tunnel, DNS, Access, Pages, D1, R2, Workers, Queues, WAF, Email Routing, cache, guarded publish, dry-run planning, approval gates, and readback verification.",
    "server_url": "https://<host>/mcp",
    "defer_loading": true
  },
  {
    "type": "tool_search"
  }
]
```

Exact headers, session behavior, auth requirements, and per-tool argument
contracts live in [docs/CLIENT-CONTRACT.md](docs/CLIENT-CONTRACT.md).

## Tool families

The public surface is intentionally mixed:

- Curated tools for product workflows with safety policy beyond raw REST calls.
- Generic `api_*` tools for guarded Cloudflare REST API v4 parity.
- Discovery helpers such as `health`, `find_tools`, and `api_parity_status`.

Use curated tools first when they exist. They encode workflow-specific dry-run
shape, validation, and readback checks. Use `api_find_operations`,
`api_get_operation`, `api_prepare_call`, `api_read`, and `api_mutate` for
Cloudflare REST API operations that do not yet have a curated workflow.
For billing or D1 usage-spike work, use `account_billing_usage` for billable
usage records and `graphql_analytics_query` for product analytics attribution.
For WAF investigations, use `waf_ruleset_summary`,
`waf_security_events_summary`, and `waf_rule_activity`. For WAF changes, use
`waf_ruleset_plan_change` to produce a stable diff, rule-cap/list validation,
and confirmation token, then `waf_ruleset_apply_change` for apply and readback.
Fall back to raw GraphQL or generic Rulesets API calls only when the curated
lifecycle tools do not cover the workflow.

See [docs/TOOL_GUIDE.md](docs/TOOL_GUIDE.md) for a product-oriented map.

## REST API parity

The generic executor is backed by `spec/cloudflare_api_catalog.v1.json`, a
compact catalog generated from Cloudflare's public OpenAPI schema. The server
does not register one MCP tool per Cloudflare endpoint. Instead, clients search
and inspect operations before invoking `api_read` or `api_mutate`.

`api_mutate` is guarded: dry-run first, confirmation token for apply, high-risk
categories denied by default, and optional human approval gates when
elicitation is enabled.

See [docs/API-PARITY.md](docs/API-PARITY.md).

## Documentation

- [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md): build, run, client setup,
  and first checks.
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md): auth, read-only mode,
  dry-run/apply, elicitation, and audit behavior.
- [docs/TOOL_GUIDE.md](docs/TOOL_GUIDE.md): curated tool families and generic
  API fallback guidance.
- [docs/CLIENT-CONTRACT.md](docs/CLIENT-CONTRACT.md): exact MCP request and
  tool argument contract.
- [docs/RUNBOOK.md](docs/RUNBOOK.md): operator rollout, verification, and
  rollback workflow.
- [docs/AGENT_ROUTING.md](docs/AGENT_ROUTING.md): when to use this server,
  Cloudflare's managed MCP servers, or Cloudflare-documented CLIs.
- [docs/CONFORMANCE_DOGFOOD.md](docs/CONFORMANCE_DOGFOOD.md): how this server
  dogfoods MCP Toolkit behavior such as strict inventory, tool search,
  deferred loading, resources, error envelopes, and release provenance.
- [docs/API-PARITY.md](docs/API-PARITY.md): OpenAPI catalog and generic
  executor policy.
- [spec/README.md](spec/README.md): tool schema snapshot workflow.
- [packaging/codex/cloudflare-managed-mcp.example.toml](packaging/codex/cloudflare-managed-mcp.example.toml):
  example Codex MCP profile for enabling official Cloudflare managed MCPs
  beside this guarded operator MCP.

## Development

Useful local checks:

```bash
cargo fmt --check
cargo test
cargo test --test mcp_stdio_smoke
CLOUDFLARE_MCP_AUTH_MODE=off cargo run -- --print-tools
```

When tool schemas intentionally change:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test tools::tests::tool_schema_snapshot_contract_is_stable
cargo test tools::tests::tool_schema_snapshot_contract_is_stable
```

GitHub Actions runs the same Rust validation lane on pull requests and pushes.
The CodeQL workflow runs analysis as a static guardrail with SARIF upload
disabled, so repositories without GitHub code scanning enabled do not fail only
because the results cannot be uploaded.

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening changes.

## Security

Do not commit Cloudflare API tokens, OAuth client secrets, R2 credentials, or
service tokens. Prefer environment variables or protected secret files outside
the repository.

For vulnerability reporting and deployment guidance, see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
