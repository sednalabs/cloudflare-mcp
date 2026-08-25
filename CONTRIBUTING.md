# Contributing

Thanks for considering a contribution to `cloudflare-mcp`.

This repository has two related purposes: it provides practical self-hosted
Cloudflare operator workflows, and it acts as a realistic integration and
stress-test environment for the Rust MCP Toolkit. Changes should have a clear
reason to belong here under at least one of those purposes.

Before adding a new Cloudflare surface, read
[docs/PROJECT_SCOPE.md](docs/PROJECT_SCOPE.md) and check whether Cloudflare's
official MCPs already cover the task. Duplication can still be useful when the
local implementation adds a real operator workflow or deliberately exercises a
reusable Toolkit capability, but endpoint parity by itself is not a goal.

## Development Setup

For normal development, a fresh clone is enough. The Toolkit crates are pinned
as public git dependencies in `Cargo.toml`, so the standard Cargo workflow does
not require a sibling checkout:

```bash
cargo build
```

If you are changing reusable Toolkit primitives at the same time, use a sibling
checkout and temporarily point Cargo at that local tree for the duration of the
Toolkit work:

```text
workspace/
  servers/
    cloudflare-mcp/
  toolkits/
    mcp-toolkit-rs/
```

## Change Guidelines

- Keep Cloudflare product-specific logic in this repository.
- Move broadly reusable MCP primitives into the Toolkit once they have been
  proven here.
- When a feature is primarily a Toolkit incubation or conformance case, state
  what reusable behavior it is intended to exercise and what should eventually
  move upstream.
- Prefer Cloudflare's official MCPs when they already solve the task and the
  local implementation would add neither operator value nor useful Toolkit
  coverage.
- Preserve strict tool inventory enforcement.
- Preserve dry-run-first behavior for mutating tools.
- Preserve curated first-class tools where workflow-specific safety policy or
  useful conformance coverage exists. Intentional retirement is allowed when
  that value has disappeared, but update the affected tests, contracts, and
  documentation in the same change.
- Do not add dependencies unless they are clearly justified.
- Do not commit generated artifacts, build outputs, logs, local state, or
  secrets.

## Documentation Guidelines

Public docs should be useful without requiring private project context or
exposing deployment details.

- Use placeholders for paths, hosts, issuers, accounts, zones, and tokens.
- Avoid organization-specific endpoint examples or internal work-item jargon.
- Describe required client/MCP capabilities rather than declaring a particular
  hosted model the current, preferred, or flagship model. Model availability
  changes independently of this repository; link to the vendor's current docs
  when a product-specific capability matters.
- Keep the README concise; put exact contracts in supporting docs.
- Keep [docs/TOOL_GUIDE.md](docs/TOOL_GUIDE.md) focused on tool selection rather
  than duplicating long operating procedures or exact response contracts.
- Put cross-document navigation in [docs/README.md](docs/README.md) when a new
  specialist guide is added.
- Update [docs/PROJECT_SCOPE.md](docs/PROJECT_SCOPE.md) when the boundary between
  local operator work, official Cloudflare MCPs, and Toolkit incubation changes.
- Update [docs/CLIENT_COMPATIBILITY.md](docs/CLIENT_COMPATIBILITY.md) when
  client-side MCP/deferred-loading/approval guidance changes.
- Update [docs/RUNBOOK.md](docs/RUNBOOK.md) when operator workflow changes.
- Update [docs/CLIENT-CONTRACT.md](docs/CLIENT-CONTRACT.md) when client-visible
  request or tool argument behavior changes.
- Update [docs/API-PARITY.md](docs/API-PARITY.md) when generic API parity
  behavior changes.
- Update [docs/CONFORMANCE_DOGFOOD.md](docs/CONFORMANCE_DOGFOOD.md) when a change
  adds or removes a deliberate Toolkit stress/conformance case.

## Validation

For behavior changes, run:

```bash
cargo fmt --check
cargo test
cargo test --test mcp_stdio_smoke
CLOUDFLARE_MCP_AUTH_MODE=off cargo run -- --print-tools
```

For intentional tool schema changes:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test tools::tests::tool_schema_snapshot_contract_is_stable
cargo test tools::tests::tool_schema_snapshot_contract_is_stable
```

For docs-only changes, run a public wording scan and verify links in the files
you touched.

## Pull Request Checklist

- The diff is scoped and reviewable.
- A new local capability has a clear operator or Toolkit-development reason to
  exist here rather than only duplicating an official endpoint.
- Reusable Toolkit behavior is separated from Cloudflare-specific integration
  where practical.
- Public docs do not contain secrets, private paths, internal-only terminology,
  or organization-specific endpoints.
- Client guidance states capabilities rather than time-sensitive model
  recommendations.
- Tool schema snapshots are updated only when the tool contract intentionally
  changes.
- Stdio smoke coverage exists for new or changed tool-call behavior.
- Validation commands and any skipped checks are listed in the PR description.
