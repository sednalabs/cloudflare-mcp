# AGENTS.md — cloudflare-mcp

## Scope and precedence
- These instructions apply to this repository.
- If another instruction file exists closer to a file you edit, that file wins.
- Do not weaken the anti-monolith, modularization, or elegance requirements from
  the workspace-level agent guidance.

## Operating intent
- Primary parity target: `cloudflared` operational workflows plus required Zero
  Trust orchestration.
- Explicit non-goal: parity with broad third-party Cloudflare MCP server ecosystems.
- Preserve private-by-default behavior and safety-critical publish controls as first-class
  requirements.

## Ops coordination
- Follow `docs/ops-coordination.md` for work item lifecycle, ownership, and progress updates.
- Keep work decomposition transferable across the broader workspace; avoid one-off process
  rules that only fit this server.

## Architecture boundaries
- Keep transport/auth/session wiring in `src/main.rs` and config parsing in `src/config.rs`.
- Keep Cloudflare REST API adapter behavior in `src/cloudflare/**`.
- Keep policy and state-machine rulebooks in focused modules:
  - `src/publish.rs`
  - `src/policy.rs`
  - `src/mutation.rs`
  - `src/verification.rs`
- Keep `src/tools.rs` orchestration-focused; do not turn it into an all-in-one monolith mixing
  transport internals and adapter implementation details.
- Reuse shared workspace primitives from `toolkits/mcp-toolkit-rs/**` before adding local
  duplicate helpers.

## Safety and security invariants (mandatory)
- Never allow non-loopback bind without auth enabled.
- Preserve strict tool inventory enforcement: only registered tools can be listed or called.
- Tool presence is not enough. Curated and generic tools changed by a patch must be
  exercised through the real MCP call path, preferably stdio, so rmcp argument extraction,
  request-context fallback, dry-run planning, and structured error behavior are covered.
- Preserve curated first-class tools for product workflows that have safety policy beyond
  raw REST execution. Do not replace them with generic `api_read`/`api_mutate` parity tools.
  The restored recovery contract is mandatory: Access gate helpers, Pages, D1 read/write
  and migrations, Queues, Workers/Observability, Email Routing, bindings discovery, and
  Bulk Redirect curated tools must remain listed, callable, discoverable, and covered by
  `server::tests::restored_recovery_tool_contract_stays_present`.
- Preserve lock-first publish semantics:
  - policy gate evaluation must happen before DNS mutation,
  - denied gates fail closed unless explicit override policy allows.
- Mutating tools must keep deterministic dry-run planning with no side effects.
- Mutating generic API calls must normalize or explicitly preserve JSON-string bodies before
  request planning and apply. Tests must cover object, escaped JSON string, invalid JSON string,
  array, and null body shapes when the tool accepts arbitrary JSON.
- Mutating tool outcomes must include structured audit metadata with correlation IDs
  (`x-correlation-id` passthrough or generated fallback).
- Keep policy post-apply invariant validation on allowlist mutations; fail closed on invariant
  violations.
- Keep emergency unpublish idempotent across repeated invocations.

## Repo hygiene
- Do not commit generated artifacts:
  - `target/`
  - `logs/`
  - `.tmp/`
- Do not commit secrets. Supply credentials via environment or service credential mechanisms.
- Never place API tokens or sensitive host details in work-item comments or public issue text.

## Documentation and contract policy
- Update `docs/RUNBOOK.md` when rollout, safety workflow, or operator procedures change.
- Update `spec/README.md` when tool contract workflow changes.
- Keep `spec/tool_schema_snapshot.v1.json` in sync with tool surface changes.
- When adding broad parity features, verify curated tool discovery with `find_tools` for
  affected products (for example `query=d1`) and add regression tests for any preserved
  first-class tool names. A passing generic API catalog search is not enough.
- Keep runtime attestation intent accurate (`parity_target=cloudflared`, explicit non-goal text).

## Testing and verification
- For behavior changes, run at least:
  - `cargo fmt --check`
  - `cargo test`
  - `cargo test --test mcp_stdio_smoke`
  - `cargo run -- --print-tools`
- When tool schemas change, run:
  - `MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test tools::tests::tool_schema_snapshot_contract_is_stable`
- For transport/auth/tool-call-boundary changes, validate the executable MCP boundary:
  - `cargo test --test mcp_stdio_smoke` for committed stdio regression coverage,
  - `mcp_probe` direct calls (`probe_handshake`, `probe_call_tool`, and
    `probe_http_smoke` when applicable) for live or release-binary smoke checks.
- For deployment or binary replacement, verify the running process, not just the symlink:
  compare the release binary hash, `--print-tools` count, and `/proc/<pid>/exe` target/hash
  for any existing `cloudflare-mcp --stdio` processes. Existing stdio sessions keep the old
  inode until restarted.
- CodeQL is a static guardrail, not proof that a tool works. Use CodeQL to catch repeat
  structural risks, but keep MCP stdio/runtime tests as the source of truth for callability.
