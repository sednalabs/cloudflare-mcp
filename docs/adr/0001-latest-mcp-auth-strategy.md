# ADR 0001: OAuth-First Auth Strategy Aligned to Latest MCP Spec

- Status: Accepted
- Date: 2026-02-24
- Owners: cloudflare-mcp maintainers

## Context

`cloudflare-mcp` exposes a Streamable HTTP MCP endpoint and performs privileged Cloudflare API
operations. The existing auth architecture had these gaps for long-term operation:

- protocol advertisement lagged behind current MCP releases,
- audience/resource binding could be under-configured in some auth profiles,
- interactive OAuth and automation compatibility paths were not clearly separated.

The intended operating model is:

- interactive OAuth for user-driven clients,
- explicit automation paths for non-interactive workflows,
- spec-aligned behavior for remote MCP authorization semantics.

## Decision

We adopt an OAuth-first, latest-spec posture with explicit compatibility modes.

1. `/mcp` remains a protected MCP resource with OAuth discovery + PRM metadata and bearer token
   validation.
2. Server protocol version is advertised as the latest MCP spec release (`2025-11-25`) by default.
3. When auth is enabled, audience/resource binding is enforced by default:
   - if `CLOUDFLARE_MCP_AUTH_AUDIENCE` is unset, it is derived from canonical resource URL.
4. OAuth validation modes requiring external issuer semantics (`jwks`, `introspection`) require
   `CLOUDFLARE_MCP_AUTH_ISSUER`.
5. Cloudflare upstream credentialing is explicit and configurable:
   - default: server-held token (`CLOUDFLARE_MCP_API_TOKEN`),
   - optional compatibility mode: request header token source (`x-cloudflare-api-token` by default),
   - optional mixed mode: request header first, then server token fallback.
6. Compatibility header mode is intentionally separate from MCP bearer auth to avoid token-passthrough
   anti-patterns for MCP authorization tokens.
7. Delegation remains supported for automation and smoke flows, but a real external issuer
   remains the preferred path for interactive OAuth clients.

## Consequences

Positive:

- clear trust-boundary separation between MCP auth and Cloudflare upstream auth,
- stronger defaults for OAuth audience/resource correctness,
- interactive OAuth remains the primary path for clients,
- automation and migration scenarios still have explicit supported modes.

Tradeoffs:

- stricter validation may require additional env configuration in existing deployments
  (`CLOUDFLARE_MCP_AUTH_ISSUER` for `jwks`/`introspection`),
- compatibility header mode introduces one additional configuration surface and must be documented
  carefully to avoid accidental broad token exposure.

## Rollout

1. Ship config + runtime behavior changes with backward-compatible defaults.
2. Update operator docs (`README.md`, `docs/CLIENT-CONTRACT.md`, `docs/RUNBOOK.md`).
3. Validate with:
   - `cargo test`
   - `cargo run -- --print-tools`
4. Follow up in adjacent servers (including `github-mcp-server`) via tracked issues to harmonize
   MCP auth posture and versioning.
