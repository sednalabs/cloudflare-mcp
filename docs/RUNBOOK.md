# Operator Runbook

This runbook describes the safe operating sequence for `cloudflare-mcp`.

Companion docs:

- [../README.md](../README.md): project overview and quick start.
- [GETTING_STARTED.md](GETTING_STARTED.md): build, run, and first checks.
- [SECURITY_MODEL.md](SECURITY_MODEL.md): safety controls and auth model.
- [CLIENT-CONTRACT.md](CLIENT-CONTRACT.md): exact MCP request and tool argument
  contract.
- [API-PARITY.md](API-PARITY.md): generic Cloudflare REST API parity model.

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
CLOUDFLARE_MCP_AUTH_MODE=off target/release/cloudflare-mcp --print-tools
```

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
```

Review the plan and policy output before apply.

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
