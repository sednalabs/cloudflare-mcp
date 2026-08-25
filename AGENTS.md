# AGENTS.md — cloudflare-mcp

## Scope and precedence
- These instructions apply to this repository.
- If another instruction file exists closer to a file you edit, that file wins.
- Do not weaken the anti-monolith, modularization, or elegance requirements from
  the workspace-level agent guidance.

## Operating intent
- Primary purpose: provide useful self-hosted Cloudflare operator workflows and
  serve as a realistic integration/conformance environment for the Rust MCP
  Toolkit.
- Broad endpoint parity with Cloudflare's official MCP catalog is not a goal.
  Use the official MCPs when they already solve the task and a local
  implementation would add neither operator value nor useful Toolkit coverage.
- A local implementation may intentionally overlap an official MCP when it adds
  a real safety/verification workflow or provides a meaningful stress case for a
  reusable Toolkit capability that should later be upstreamed.
- `cloudflared` and Zero Trust workflows remain important product inputs, but
  they are not the universal parity target for the repository.
- Preserve private-by-default behavior and safety-critical publish controls as
  first-class requirements.
- Use `docs/PROJECT_SCOPE.md` as the project-level decision rule for adding,
  retaining, or retiring curated local surfaces.

## Ops coordination
- Follow `docs/ops-coordination.md` for work item lifecycle, ownership, and
  progress updates.
- Keep work decomposition understandable from repository-visible context and
  transferable across the broader workspace; avoid one-off process rules that
  require private chat history.

## Architecture boundaries
- Keep transport/auth/session wiring in `src/main.rs` and config parsing in
  `src/config.rs`.
- Keep Cloudflare REST API adapter behavior in `src/cloudflare/**`.
- Keep policy and state-machine rulebooks in focused modules:
  - `src/publish.rs`
  - `src/policy.rs`
  - `src/mutation.rs`
  - `src/verification.rs`
- Keep `src/tools.rs` orchestration-focused; do not turn it into an all-in-one
  monolith mixing transport internals and adapter implementation details.
- Reuse shared primitives from `mcp-toolkit-rs` before adding local duplicate
  helpers.
- When a reusable primitive is first proven in this repository, keep the
  Cloudflare-specific integration local but move the general mechanism into the
  Toolkit once the contract is understood and tested.

## Safety and security invariants (mandatory)
- Never allow non-loopback bind without auth enabled.
- Preserve strict tool inventory enforcement: only registered tools can be
  listed or called.
- Tool presence is not enough. Curated and generic tools changed by a patch must
  be exercised through the real MCP call path, preferably stdio, so rmcp
  argument extraction, request-context fallback, dry-run planning, and
  structured error behavior are covered.
- Do not replace a curated tool that currently carries distinct safety,
  verification, recovery, or conformance value with a generic
  `api_read`/`api_mutate` path merely because the underlying endpoint is
  reachable.
- Existing curated families are not immutable. Intentional simplification or
  retirement is allowed when the official services make a surface redundant
  and it no longer provides meaningful operator or Toolkit-conformance value.
  Such a change must update the tool inventory, schema snapshot, regression
  tests, client contract, routing guidance, and migration/replacement notes in
  the same reviewed change.
- Until intentionally changed, keep the existing restored recovery contract and
  its `server::tests::restored_recovery_tool_contract_stays_present` coverage
  consistent with the registered tool surface. Do not silently drop Access gate
  helpers, Pages, D1 read/write and migrations, Queues, Workers/Observability,
  Email Routing, bindings discovery, or Bulk Redirect tools.
- Preserve lock-first publish semantics:
  - policy gate evaluation must happen before DNS mutation,
  - denied gates fail closed unless explicit override policy allows.
- Mutating tools must keep deterministic dry-run planning with no side effects.
- Mutating generic API calls must normalize or explicitly preserve JSON-string
  bodies before request planning and apply. Tests must cover object, escaped
  JSON string, invalid JSON string, array, and null body shapes when the tool
  accepts arbitrary JSON.
- Mutating tool outcomes must include structured audit metadata with correlation
  IDs (`x-correlation-id` passthrough or generated fallback).
- Keep policy post-apply invariant validation on allowlist mutations; fail
  closed on invariant violations.
- Keep emergency unpublish idempotent across repeated invocations.

## Toolkit incubation and upstreaming
- A Toolkit-driven feature must have a concrete reusable hypothesis, not merely
  provide another Cloudflare wrapper.
- Exercise the behavior through a realistic MCP boundary and workload here when
  that gives stronger evidence than a synthetic Toolkit-only fixture.
- Keep provider-specific policy and request construction in this repository.
- Once reusable behavior is proven, upstream the general primitive to
  `mcp-toolkit-rs`, update the pinned Toolkit revision, and remove local
  duplication where practical.
- Retain the Cloudflare integration afterward only when it still provides useful
  operator behavior or ongoing conformance/stress coverage.
- Update `docs/CONFORMANCE_DOGFOOD.md` when adding or retiring a deliberate
  Toolkit conformance case.

## Repo hygiene
- Do not commit generated artifacts:
  - `target/`
  - `logs/`
  - `.tmp/`
- Do not commit secrets. Supply credentials via environment or service
  credential mechanisms.
- Never place API tokens or sensitive host details in work-item comments or
  public issue text.

## Documentation and contract policy
- Keep all repository documentation understandable as public project material;
  do not require internal work-item names or private discussion for context.
- Update `docs/PROJECT_SCOPE.md` when the boundary between local operator value,
  official Cloudflare MCP coverage, and Toolkit incubation changes.
- Update `docs/RUNBOOK.md` when rollout, safety workflow, or operator procedures
  change.
- Update `spec/README.md` when tool contract workflow changes.
- Keep `spec/tool_schema_snapshot.v1.json` in sync with tool surface changes.
- When adding broad parity features, verify curated tool discovery with
  `find_tools` for affected products (for example `query=d1`) and add regression
  tests for any preserved first-class tool names. A passing generic API catalog
  search is not enough.
- Keep runtime attestation and public descriptions aligned with the current
  project scope rather than historical parity language.

## Testing and verification
- For behavior changes, run at least:
  - `cargo fmt --check`
  - `cargo test`
  - `cargo test --test mcp_stdio_smoke`
  - `cargo run -- --print-tools`
- When tool schemas change, run:
  - `MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test tools::tests::tool_schema_snapshot_contract_is_stable`
- For transport/auth/tool-call-boundary changes, validate the executable MCP
  boundary:
  - `cargo test --test mcp_stdio_smoke` for committed stdio regression coverage,
  - `mcp_probe` direct calls (`probe_handshake`, `probe_call_tool`, and
    `probe_http_smoke` when applicable) for live or release-binary smoke checks.
- For deployment or binary replacement, verify the running process, not just
  the symlink: compare the release binary hash, `--print-tools` count, and
  `/proc/<pid>/exe` target/hash for any existing `cloudflare-mcp --stdio`
  processes. Existing stdio sessions keep the old inode until restarted.
- CodeQL is a static guardrail, not proof that a tool works. Use CodeQL to catch
  repeat structural risks, but keep MCP stdio/runtime tests as the source of
  truth for callability.
