# MCP Toolkit Conformance Dogfood

`cloudflare-mcp` is a real-world integration, conformance, and stress-test server
for the Rust MCP Toolkit. Its Cloudflare workload is deliberately large and
varied enough to exercise discovery, deferred loading, strict inventory,
resources, auth, policy, error shaping, mutation workflows, and release
provenance under realistic agent pressure.

That role is complementary to the server's operator purpose. It is not a claim
that this repository should replace Cloudflare's official managed MCPs for the
freshest product coverage.

Use official Cloudflare MCPs for current documentation, broad Code Mode API
exploration, and product-specific managed capabilities. Use this repository when
a self-hosted operator workflow adds useful controls, or when a realistic
Cloudflare integration provides a meaningful test bed for reusable Toolkit
behavior.

## Incubating Toolkit behavior here

It is acceptable for this repository to implement functionality that overlaps
with an official Cloudflare MCP when the implementation is deliberately being
used to develop or stress-test a reusable MCP capability.

Good incubation candidates have an explicit reusable question, for example:

- can a large tool inventory remain searchable and defer-loadable without
  weakening strict dispatch policy?
- can read-only mode consistently affect discovery and direct invocation?
- can elicitation approval bind the exact operation being approved?
- can authentication, resources, error envelopes, and mutation evidence remain
  consistent across stdio and Streamable HTTP?
- can release provenance tie a built binary back to its source and tool
  contract?

The Cloudflare-specific integration provides the realistic workload; reusable
mechanics should move to `mcp-toolkit-rs` once they are sufficiently proven.
After upstreaming, keep the local integration only when it still provides useful
operator behavior or ongoing conformance coverage. Toolkit incubation should be
purposeful rather than a reason to mirror Cloudflare's product catalog.

See [PROJECT_SCOPE.md](PROJECT_SCOPE.md) for the corresponding project-scope
rule.

## Conformance Matrix

| Toolkit behavior | Cloudflare MCP proof |
| --- | --- |
| Stdio transport and RMCP argument extraction | `cargo test --test mcp_stdio_smoke` exercises the compiled binary through JSON-RPC. |
| Streamable HTTP transport and non-loopback auth safety | `src/main.rs` and `docs/CLIENT-CONTRACT.md` cover HTTP bind/auth invariants. |
| Strict tool inventory | `server::tests::strict_inventory_denies_unregistered_tools` and `stdio_boundary_covers_large_catalog_deferred_loading_contract` reject unknown tools. |
| Large-catalog listing | `stdio_boundary_covers_large_catalog_deferred_loading_contract` asserts `tools/list` exposes the 100+ tool catalog. |
| Tool search and deferred loading | `find_tools` tests in `src/tools.rs`, `tests/mcp_stdio_smoke.rs`, and `cloudflare-mcp://openai/tool-search-config` cover narrowed `allowed_tools`, optional schemas, and OpenAI `defer_loading`. |
| Read-only filtering | `server::tests::read_only_policy_hides_mutating_tools` and read-only `find_tools` smoke assertions keep mutating tools out of read-only discovery. |
| Curated-only fallback | `server::tests::curated_only_policy_hides_api_parity_tools` verifies generic `api_*` hiding while curated tools remain available. |
| Resources | `resources::tests::openai_tool_search_config_uses_deferred_loading_and_safe_approval_default` and the stdio resource read smoke cover resource payloads through both direct and MCP paths. |
| Elicitation gates | `config::tests::*elicitation*` and `server::tests::*elicitation*` cover mandatory dangerous-tool gates, dry-run bypass, and read-action bypasses. |
| Error envelopes | Stdio smoke tests assert structured tool errors for invalid plans, denied mutations, D1 validation failures, and unsupported tool paths. |
| Mutation audit metadata | Stdio smoke tests for `api_mutate`, account API tokens, WAF apply, portal bridge, Workers upload, and R2/D1 operations assert dry-run plans, confirmation tokens, and correlation/audit fields. |
| Schema snapshots | `tools::tests::tool_schema_snapshot_contract_is_stable` guards the committed tool schema contract. |
| Release provenance | `scripts/generate-release-provenance.sh` and the Rust Validation workflow tie source commit, dirty state, binary hash, tool count, inventory hash, schema/catalog hashes, and pinned `mcp-toolkit-rs` revision. |

## Regression Policy

When a Toolkit behavior regresses in another server, add the smallest
fixture-backed case here if `cloudflare-mcp` can reproduce it through a real MCP
boundary. Prefer stdio or Streamable HTTP JSON-RPC checks over direct handler
tests when the failure involves transport, request context, schema extraction,
tool list visibility, deferred loading, or structured MCP errors.

Keep these cases secret-free. Use fake Cloudflare API fixtures or deterministic
dry-run planning unless live Cloudflare authorization is the behavior under
test. If the root cause is in `mcp-toolkit-rs`, fix the Toolkit crate and update
the pinned revision here as part of the same change when practical.
