# Documentation

This directory contains the public documentation for `cloudflare-mcp`.

If you are new to the project, start with the repository
[README](../README.md), then use this page to choose the level of detail you
need.

## Start here

- [GETTING_STARTED.md](GETTING_STARTED.md): build, run, authentication profiles,
  local stdio/HTTP setup, and first checks.
- [TOOL_GUIDE.md](TOOL_GUIDE.md): quick workflow-to-tool map.
- [AGENT_ROUTING.md](AGENT_ROUTING.md): choose between this server,
  Cloudflare's official MCPs, and Cloudflare-documented CLIs.
- [CLIENT_COMPATIBILITY.md](CLIENT_COMPATIBILITY.md): capability-based client
  guidance, deferred loading/tool search, approval, and version-neutral examples.

## Project scope and official Cloudflare MCPs

- [PROJECT_SCOPE.md](PROJECT_SCOPE.md): what belongs in this repository and the
  two reasons a local capability may be worth implementing: operator value or
  meaningful Rust MCP Toolkit incubation/conformance value.
- [OFFICIAL_MCP_COMPARISON.md](OFFICIAL_MCP_COMPARISON.md): practical comparison
  with Cloudflare Code Mode and product-specific managed MCPs.
- [CONFORMANCE_DOGFOOD.md](CONFORMANCE_DOGFOOD.md): how this server exercises,
  stress-tests, and can incubate reusable Rust MCP Toolkit behavior.

## Operator references

- [RUNBOOK.md](RUNBOOK.md): production operating procedures, rollout,
  verification, recovery, and rollback.
- [D1_MIGRATIONS.md](D1_MIGRATIONS.md): conceptual guide to the curated D1
  migration, retained-custody, reconciliation, and bootstrap lifecycles.
- [SECURITY_MODEL.md](SECURITY_MODEL.md): inbound auth, upstream credentials,
  read-only mode, mutation approval, and trust boundaries.
- [API-PARITY.md](API-PARITY.md): generic REST catalog, guarded executor, deny
  policy, and relationship to Cloudflare Code Mode.

## Exact client and tool contracts

- [CLIENT-CONTRACT.md](CLIENT-CONTRACT.md): exact MCP transport, auth, request,
  argument, and response contract. Treat capability descriptions as normative;
  client/model product versions can change independently of this repository.
- [../spec/README.md](../spec/README.md): committed tool schema snapshot and API
  catalog workflow.

The client contract is intentionally detailed because it documents exact public
behavior. The tool guide, client compatibility guide, and D1 guide are
navigation layers, not substitutes for that contract.

## Contributors and maintainers

- [../CONTRIBUTING.md](../CONTRIBUTING.md): contribution scope, development
  checks, and documentation expectations.
- [ops-coordination.md](ops-coordination.md): public coordination guidance for
  substantial changes.
- [adr/0001-latest-mcp-auth-strategy.md](adr/0001-latest-mcp-auth-strategy.md):
  accepted authentication architecture decision.

## Choosing the right level of documentation

For most tasks:

1. use `TOOL_GUIDE.md` to choose the tool;
2. use `CLIENT-CONTRACT.md` when exact fields or behavior matter;
3. use `RUNBOOK.md` when performing a production-affecting or recovery
   operation.

Use `CLIENT_COMPATIBILITY.md` when configuring a client or deciding which
client-side MCP features are required. For D1 migrations, insert
`D1_MIGRATIONS.md` between steps 1 and 2 to understand the lifecycle before
working from the exact contract.
