# Operator Runbook

This runbook describes the safe operating sequence for `cloudflare-mcp`.

Companion docs:

- [../README.md](../README.md): project overview and quick start.
- [GETTING_STARTED.md](GETTING_STARTED.md): build, run, and first checks.
- [SECURITY_MODEL.md](SECURITY_MODEL.md): safety controls and auth model.
- [CLIENT-CONTRACT.md](CLIENT-CONTRACT.md): exact MCP request and tool argument
  contract.
- [AGENT_ROUTING.md](AGENT_ROUTING.md): agent-facing routing between this
  operator MCP, Cloudflare managed MCP servers, and Cloudflare-documented CLIs.
- [API-PARITY.md](API-PARITY.md): generic Cloudflare REST API parity model.
- [../packaging/codex/cloudflare-managed-mcp.example.toml](../packaging/codex/cloudflare-managed-mcp.example.toml):
  Codex profile template for placing this guarded server beside Cloudflare's
  official managed MCP endpoints.

## Preconditions

Before using the server for production-like changes:

- Configure a Cloudflare API credential source:
  - `CLOUDFLARE_MCP_API_TOKEN`, or
  - `CLOUDFLARE_MCP_API_TOKEN_SOURCE=header|header_or_config`.
- Configure account and zone defaults or pass IDs per call:
  - `CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID`
  - `CLOUDFLARE_MCP_DEFAULT_ZONE_ID`
- Enable MCP auth before any non-loopback bind.
- Use least-privilege Cloudflare API tokens.
- Keep secrets in environment variables or protected files outside the
  repository.

Recommended preflight checks:

```bash
cargo test tools::tests::tool_schema_snapshot_contract_is_stable
cargo test --test mcp_stdio_smoke
CLOUDFLARE_MCP_AUTH_MODE=off cargo run -- --print-tools
```

For release binaries, verify the promoted binary rather than only the source
tree:

```bash
CLOUDFLARE_MCP_AUTH_MODE=off cargo build --release
CLOUDFLARE_MCP_AUTH_MODE=off target/release/cloudflare-mcp --print-tools
scripts/generate-release-provenance.sh \
  --binary target/release/cloudflare-mcp \
  --output .tmp/release-provenance.json
jq . .tmp/release-provenance.json
```

If an existing `cloudflare-mcp --stdio` process is already serving traffic,
verify that process as well as the file on disk. Stdio sessions keep the old
executable inode until restarted, so a promoted symlink or copied binary is not
proof that the live process has changed:

```bash
pgrep -af 'cloudflare-mcp.*--stdio'
readlink -f /proc/<pid>/exe
sha256sum /proc/<pid>/exe target/release/cloudflare-mcp
```

The provenance manifest is secret-free. It records the source commit, dirty
state, binary SHA-256 and size, registered tool count, normalized tool inventory
hash, committed schema/catalog hashes, and pinned `mcp-toolkit-rs` revision.
Treat it as the release note for an installed binary. For a promoted symlink or
versioned install directory, keep the manifest beside the binary or in the
release artifact bundle so agents can compare:

- source commit versus repository `main` or the release tag,
- binary SHA-256 versus the installed file,
- tool count and inventory hash versus `--print-tools`,
- schema snapshot hash versus `spec/tool_schema_snapshot.v1.json`,
- `/proc/<pid>/exe` hash for any already-running stdio process.

## Safety Profiles

### Read-Only

Use read-only mode when no mutation should be possible:

```bash
export CLOUDFLARE_MCP_READ_ONLY=1
```

Expected behavior:

- `tools/list` includes only read-only tools.
- Mutating tools are denied.
- `health` reports `read_only_mode=true`.

### Curated Tools Only

Use curated-tools-only mode when broad generic REST execution should be hidden:

```bash
export CLOUDFLARE_MCP_API_PARITY_ENABLED=0
```

Expected behavior:

- Generic `api_*` parity tools are hidden and denied.
- Curated Cloudflare workflow tools remain governed by normal auth and
  read-only policy.

### Approval-Gated Apply

Use elicitation when dangerous apply calls require human approval:

```bash
export CLOUDFLARE_MCP_ELICITATION_ENABLED=1
export CLOUDFLARE_MCP_ELICITATION_APPLY_ONLY=1
```

Expected behavior:

- Configured dangerous tools prompt before apply.
- Dry-run calls bypass approval by default.
- Clients without elicitation capability fail closed unless explicitly
  configured otherwise.
- Approval prompts include a request digest that must be echoed in the response.

## Baseline Read-Only Audit

When the task needs broad or current Cloudflare discovery before a guarded
operator action, add the relevant managed MCP endpoints from
`packaging/codex/cloudflare-managed-mcp.example.toml` to the agent profile.
Use OAuth for interactive sessions or an out-of-repository bearer token for
automation. Treat a configured managed endpoint as connection setup only:
account/API endpoints still need Cloudflare authorization before read-only
calls work.

Before relying on a managed endpoint, run a safe smoke check:

```bash
curl -sS -X POST https://docs.mcp.cloudflare.com/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cloudflare-mcp-smoke","version":"0.0.0"}}}'
```

For account/API endpoints such as `https://mcp.cloudflare.com/mcp` or
`https://graphql.mcp.cloudflare.com/mcp`, an unauthenticated `401 invalid_token`
is an acceptable pre-auth smoke result. The next proof must be an authorized
read-only MCP call through the target client or an allowlisted probe profile.

For this self-hosted server in Streamable HTTP mode, distinguish MCP auth
readiness from Cloudflare API capability readiness:

```text
mcp_probe probe_http_smoke url=http://127.0.0.1:9501/mcp expect_auth_required=true
mcp_probe probe_handshake transport=streamable-http url=http://127.0.0.1:9501/mcp expect_auth_required=true
```

Those checks prove the HTTP/OAuth metadata and unauthenticated challenge shape.
They do not prove a logged-in MCP client. The first authenticated pre-mutation
tool call should be:

```text
tools/call name=capabilities_check arguments='{"account_id":"<account_id>","zone_id":"<zone_id>","expected_zone_name":"<zone_name>","require_explicit_zone_id":true}'
```

Treat `preflight.ok=false` as a stop condition until every entry in
`preflight.findings` is understood. In particular, `target.zone_id_from_default`
means the workflow is relying on `CLOUDFLARE_MCP_DEFAULT_ZONE_ID`; pass the
intended zone explicitly for DNS, Pages, Access, Worker, and publish work.

Capture current state before mutation:

```text
tools/call name=list_tunnels arguments='{"account_id":"<account_id>"}'
tools/call name=list_dns_records arguments='{"zone_id":"<zone_id>","hostname":"<hostname>"}'
tools/call name=list_access_apps arguments='{"account_id":"<account_id>","hostname":"<hostname>"}'
tools/call name=publish_preflight arguments='{"account_id":"<account_id>","hostname":"<hostname>"}'
```

Record:

- Selected tunnel identity.
- Existing DNS route state.
- Existing Access app and policy state.
- Publish preflight decision code and reason.

## Dry-Run Planning

Run mutating tools with `dry_run=true` first. Include `x-correlation-id` on
mutating requests so dry-run, apply, and rollback evidence can be linked.

Examples:

```text
tools/call name=ensure_tunnel arguments='{
  "account_id":"<account_id>",
  "tunnel_name":"<tunnel_name>",
  "dry_run":true
}'

tools/call name=upsert_access_app arguments='{
  "account_id":"<account_id>",
  "hostname":"<hostname>",
  "app_name":"<app_name>",
  "dry_run":true
}'

tools/call name=lock_first_publish arguments='{
  "account_id":"<account_id>",
  "zone_id":"<zone_id>",
  "hostname":"<hostname>",
  "target":"<target>",
  "dry_run":true
}'

tools/call name=workers_upload_script arguments='{
  "account_id":"<account_id>",
  "script_name":"<worker_script>",
  "main_module":"index.js",
  "script_path":"dist/worker/index.js",
  "metadata":{"compatibility_date":"YYYY-MM-DD"},
  "dry_run":true
}'
```

Review the plan and policy output before apply. For `workers_upload_script`,
review `upload.sha256`, `upload.metadata_sha256`, and `upload.metadata_keys`;
the tool intentionally reports digests and keys instead of raw Worker metadata
values. Apply by echoing `required_confirmation_token` in
`confirmation_token`. Treat `workers.upload_readback_mismatch` as a failed
deployment proof even when Cloudflare accepted the upload request, because the
settings readback did not match the requested module.

For projects that already use Wrangler to build a multipart Worker bundle, pass
`multipart_path` instead of `script_path`/`script_content`/`main_module`.
The MCP infers `content_type` from a leading multipart boundary when possible;
otherwise pass `content_type:"multipart/form-data; boundary=<boundary>"`.
Multipart uploads still require dry-run review and the confirmation token, but
`readback_verification` reports module-name verification as not applicable
because the bundle owns its module graph.

## Apply Sequence

For exposure workflows, use this order:

1. Ensure or identify the tunnel.
2. Generate and review ingress configuration.
3. Ensure Access app and policies.
4. Run `publish_preflight`.
5. Run `lock_first_publish` with `dry_run=true`.
6. Apply `lock_first_publish` only after the plan is accepted.
7. Verify DNS with `verify_dns_route`.
8. Verify HTTP state with `verify_http_gate`.

Do not bypass publish preflight unless the policy explicitly permits override
and the operator records a reason.

## Generic API Parity Workflow

Prefer curated tools when available. For operations without a curated tool:

```text
tools/call name=api_find_operations arguments='{"query":"<product or endpoint>"}'
tools/call name=api_get_operation arguments='{"operation_id":"<operation-id>"}'
tools/call name=api_prepare_call arguments='{"operation_id":"<operation-id>","path_params":{},"query_params":{}}'
tools/call name=api_read arguments='{"operation_id":"<get-operation-id>","path_params":{},"query":{}}'
tools/call name=api_mutate arguments='{"operation_id":"<mutating-operation-id>","path_params":{},"body":{},"dry_run":true}'
```

`api_mutate` apply calls require the dry-run confirmation token. Denied
high-risk categories fail closed.

For billing or D1 usage-spike investigations:

```text
tools/call name=account_billing_usage arguments='{"mode":"paygo","from":"<iso-start>","to":"<iso-end>"}'
tools/call name=graphql_analytics_query arguments='{"query":"query D1Usage($accountTag: string!) { viewer { accounts(filter: { accountTag: $accountTag }) { d1AnalyticsAdaptiveGroups(limit: 10000) { sum { rowsRead rowsWritten readQueries writeQueries } dimensions { date databaseId } } } } }","variables":{"accountTag":"<account-id>"}}'
```

Use billing usage for billable records and GraphQL analytics for attribution.
The REST executor derives path parameters from URL templates, so operations with
stale catalog parameter metadata should not send literal `{account_id}` paths.

For WAF rule and Security Events investigations:

```text
tools/call name=waf_ruleset_summary arguments='{"scope":"zone","phases":["custom","managed","ratelimit"],"include_rules":true}'
tools/call name=waf_security_events_summary arguments='{"window_hours":24,"group_by":["action","source","host","path","rule"],"sample_limit":10}'
tools/call name=waf_rule_activity arguments='{"rule_id":"<rule-id>","window_hours":24,"phases":["custom","managed","ratelimit"]}'
```

WAF Rulesets are read through the Ruleset Engine entrypoint phases
`http_request_firewall_custom`, `http_request_firewall_managed`, and
`http_ratelimit`. Security Events analytics use Cloudflare Analytics GraphQL
dataset `firewallEventsAdaptive`; a single HTTP request can produce multiple
security events and large windows may be sampled.

## R2 Object Workflow

Inspect before reading or writing:

```text
tools/call name=r2_inspect_object arguments='{"bucket_name":"<bucket>","object_key":"<key>"}'
```

For large or binary objects, use file response mode:

```text
tools/call name=r2_get_object arguments='{
  "bucket_name":"<bucket>",
  "object_key":"<key>",
  "response_mode":"file",
  "output_path":"/path/to/output/object.bin",
  "create_parent_dirs":true
}'
```

For writes, run dry-run first:

```text
tools/call name=r2_put_object arguments='{
  "bucket_name":"<bucket>",
  "object_key":"<key>",
  "content_text":"<content>",
  "dry_run":true
}'
```

## External Service Bridge Workflow

The optional external service bridge is for deployments that need to call
approved operator endpoints with server-held credentials.

Before enabling it:

- Configure only HTTPS allowlist prefixes that the server should call.
- Store credentials outside the repository.
- Use dry-run before live requests.
- Review sanitized response output and audit metadata.

Example dry-run:

```text
tools/call name=portal_agent_request arguments='{
  "url":"https://ops.example.com/api/agent/task",
  "method":"POST",
  "body":{"title":"Example task","content":"..."},
  "use_agent_token":true,
  "use_access_service_token":false,
  "dry_run":true
}'
```

## Rollback and Containment

For accidental exposure or failed verification:

1. Run `emergency_unpublish` with `dry_run=true`.
2. Apply `emergency_unpublish` after reviewing the plan.
3. Re-run `verify_dns_route`.
4. Re-run `verify_http_gate`.
5. Inspect Access app and policy state.
6. Record the correlation ID and final verification state.

`emergency_unpublish` is idempotent across repeated invocations.

## Validation For Changes

For docs-only changes, scan public wording and verify links.

GitHub Actions also runs CodeQL as a static-analysis guardrail. SARIF upload is
disabled in this repository's CodeQL workflow, so the guardrail can run even
when GitHub code scanning is not enabled for the repository.

For tool, transport, auth, or runtime behavior changes:

```bash
cargo fmt --check
cargo test
cargo test --test mcp_stdio_smoke
CLOUDFLARE_MCP_AUTH_MODE=off cargo run -- --print-tools
```

For tool schema changes:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test tools::tests::tool_schema_snapshot_contract_is_stable
cargo test tools::tests::tool_schema_snapshot_contract_is_stable
```

CodeQL and static checks are useful guardrails, but MCP stdio/runtime tests are
the source of truth for tool callability.
