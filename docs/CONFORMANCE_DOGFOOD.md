# MCP Toolkit Conformance Dogfood

`cloudflare-mcp` is the large-catalog dogfood server for Sedna MCP Toolkit
behavior. It should stay broad enough to exercise discovery, deferred loading,
strict inventory, resources, auth, policy, error shaping, and release
provenance under realistic agent pressure.

This is not a claim that the server replaces Cloudflare's official managed MCPs
for the freshest product coverage. Use official managed MCPs for current
Cloudflare docs, Code Mode API exploration, GraphQL/product analytics, and
product-specific discovery. Use this server to prove that Sedna's governed MCP
surface remains searchable, defer-loadable, attestable, reproducible, and safe
for operator workflows.

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

When a toolkit behavior regresses in another Sedna MCP server, add the smallest
fixture-backed case here if `cloudflare-mcp` can reproduce it through a real MCP
boundary. Prefer stdio or Streamable HTTP JSON-RPC checks over direct handler
tests when the failure involves transport, request context, schema extraction,
tool list visibility, deferred loading, or structured MCP errors.

Keep these cases secret-free. Use fake Cloudflare API fixtures or deterministic
dry-run planning unless live Cloudflare authorization is the behavior under
test. If the root cause is in `mcp-toolkit-rs`, fix the toolkit crate and update
the pinned revision here in the same tracked lane.
