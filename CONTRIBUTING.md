# Contributing

Thanks for considering a contribution to `cloudflare-mcp`.

This repository is both a Cloudflare operator MCP server and a reference
implementation for the Rust MCP Toolkit. Changes should preserve that dual
purpose: practical operator value, small reviewable diffs, and reusable MCP
patterns where they genuinely belong.

## Development Setup

Use the workspace layout described in [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md):

```text
workspace/
  servers/
    cloudflare-mcp/
  toolkits/
    mcp-toolkit-rs/
```

Then run:

```bash
cargo build
```

## Change Guidelines

- Keep Cloudflare product logic in this repository.
- Move only broadly reusable MCP primitives into the Toolkit.
- Preserve strict tool inventory enforcement.
- Preserve dry-run-first behavior for mutating tools.
- Preserve curated first-class tools where workflow-specific safety policy
  exists.
- Do not add dependencies unless they are clearly justified.
- Do not commit generated artifacts, build outputs, logs, local state, or
  secrets.

## Documentation Guidelines

Public docs should be useful without exposing private deployment details.

- Use placeholders for paths, hosts, issuers, accounts, zones, and tokens.
- Avoid organization-specific endpoint examples.
- Keep README concise; put exact contracts in supporting docs.
- Update [docs/RUNBOOK.md](docs/RUNBOOK.md) when operator workflow changes.
- Update [docs/CLIENT-CONTRACT.md](docs/CLIENT-CONTRACT.md) when client-visible
  request or tool argument behavior changes.
- Update [docs/API-PARITY.md](docs/API-PARITY.md) when generic API parity
  behavior changes.

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
- Public docs do not contain secrets, private paths, or organization-specific
  endpoints.
- Tool schema snapshots are updated only when the tool contract intentionally
  changes.
- Stdio smoke coverage exists for new or changed tool-call behavior.
- Validation commands and any skipped checks are listed in the PR description.
