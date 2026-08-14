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
- Enable MCP auth before any non-loopback bind. Set both
  `CLOUDFLARE_MCP_AUTH_RESOURCE_URL` and `CLOUDFLARE_MCP_AUTH_AUDIENCE` to
  explicit HTTPS URLs; non-loopback binds do not derive or accept HTTP values.
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

## Exact-byte D1 migration manifests

Use `d1_apply_migration_manifest` for an approval-gated D1 migration family.
First run it with `dry_run=true`; retain the returned `plan_sha256`, which is
bound to the exact SQL bytes and current Wrangler ledger prefix. A live call
must submit that value as `approved_plan_sha256` and configure
`CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT` to a pre-created, operator-owned,
non-group/world-writable directory shared by every MCP process that can target
the database. On Linux the root must be an absolute real directory owned by the
current operator with mode `0700` (or stricter), and every non-sticky ancestor
must be non-writable. The MCP permanently creates one private target directory
per account/database. It retains held root, target, guard and active file
descriptors while an apply is in progress. The target contains a permanent
`guard.lock`, acquired with a cross-process file lock, and terminal evidence such as
`retired.<nonce>.lease.json`; neither is cleanup material. While holding that
guard, the MCP writes `active.lease.json` with mode `0600` and synchronizes the
directory. Every active, abort and retirement namespace transition is relative
to the held target directory descriptor; replacing the target pathname cannot
redirect it into a replacement directory. It revalidates root, ancestors,
directory, guard, identity and mode before every provider boundary. Do not use
a shared writable directory or manually rename or remove any lease evidence by
pathname.

The exact-byte manifest boundary accepts at most 16 MiB of aggregate SQL and
moves the supplied manifest into validation without cloning its SQL strings.
Split a larger migration family before review rather than increasing this
operator-surface memory bound.

A later invocation stops before provider I/O when it sees an active or
`retiring.lease.json` entry, including one that is malformed, a symlink or
non-regular. It must be resolved only through governed recovery work item
`w11990`, never inferred stale or reclaimed. Normal terminal completion moves
the active file under the held guard to `retiring.lease.json`, synchronizes the
target directory, then records `retired.<nonce>.lease.json` without replacement
and synchronizes again. A failed synchronization restores the exact active
entry or leaves active/retiring evidence as an explicit blocker. A failed
creation is retained as
`aborted-create.<nonce>.lease.json`; production code never unlinks a lease file
or directory. The manifest tool never reopens a migration directory after
review and never retries an ambiguous provider write. An unknown outcome retains
the active target lease: reconcile provider ledger evidence and the reported
lease identity before any governed recovery. A matching ledger filename is only
an observation: it does not attest to the reviewed SQL bytes or complete
provider transaction, and therefore never authorizes lease release after an
ambiguous apply. This guarantee is limited to a trusted Linux filesystem that
supports working `renameat2(RENAME_NOREPLACE)`, directory `fsync`, and advisory
file locks. It is a shared-filesystem lease, not a Cloudflare-distributed lock;
cross-host or other shared-filesystem semantics require separate proof.
Separate provider/distributed coordination remains required when MCP instances
do not share that root. `w11990` remains the governed recovery path for
retained, malformed, or tampered evidence. Non-Linux installations or
unsupported filesystems fail closed before provider I/O.

For CI-built release bundles, the `Rust Validation` workflow uploads a
downloadable artifact named `cloudflare-mcp-linux-x86_64-stdio-<git-sha>` that
contains:

- `target/release/cloudflare-mcp`
- `.tmp/release-provenance.json`

This is the preferred install source when the operator wants the local machine
to run exactly the binary GitHub Actions validated. Example retrieval:

```bash
gh run download <run-id> \
  --repo sednalabs/cloudflare-mcp \
  --name cloudflare-mcp-linux-x86_64-stdio-<git-sha> \
  --dir /tmp/cloudflare-mcp-release-<git-sha>
```

After download, compare the installed file and the artifact manifest before
promoting a new `current` symlink or replacing the current binary in a versioned
install directory.

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

Before the baseline audit, a hosted deployment may enroll its Cloudflare grant
without copying an API token to the host:

1. Register a private Cloudflare OAuth client for the owning account with
   `authorization_code` and `refresh_token` grants, the exact HTTPS callback
   `https://<host>/oauth/cloudflare/callback`, and reviewed dot-delimited scopes.
2. Put the client secret in an owner-only secret file and configure the
   `CLOUDFLARE_MCP_UPSTREAM_OAUTH_*` environment values documented in the
   README. Leave the refresh-token cache outside the source checkout.
3. Start the service and call `cloudflare_auth_status`. It must report OAuth
   enabled, a configured client and callback, and no grant on first use.
4. Call `cloudflare_auth_login`, open its short-lived authorization URL, and
   complete Cloudflare consent. For stdio on a remote desktop host, register a
   fixed `http://127.0.0.1:<port>/oauth/cloudflare/callback` URI so the MCP
   process can own the loopback listener. Do not paste or log the callback URL.
   Poll status until `last_login_status=succeeded`.
5. Call `cloudflare_auth_probe`. Continue only when it reports
   `credential_verified=true`.

If enrollment fails, start a fresh login rather than replaying an old callback.
To remove local custody, call `cloudflare_auth_logout` first without and then
with `confirm=true`; revoke the application separately in Cloudflare when full
revocation is required.

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

When a create-only module upload returns `main_module:null` in settings, that
field is not treated as creation proof. The tool binds the upload response etag
to one exact listing entry and one version detail's `resources.script.etag`,
handlers, and a structurally valid named-handler array (which may be empty).
Any handler names and export members must be unique, nonblank, and byte-exact;
leading or trailing whitespace fails closed. The default
and named handler arrays may each be empty, but at least one valid entrypoint
must exist overall. Version lists must carry exhaustive authoritative
pagination metadata and are reread after the detail; missing, truncated,
duplicate, malformed, ambiguous, or conflicting records stop the operation.
The response contains only a sanitized attestation, never raw version metadata.

For a first-install-only deployment, add `"create_only":true` to both the
dry-run and apply calls. The confirmation token binds this flag, and apply sends
Cloudflare's atomic `If-None-Match: *` precondition. A pre-existing script must
end with `workers.upload_create_only_conflict`; do not retry or fall back to an
unconditional upload. Timeout, transport, response-read/decoding, retryable 5xx,
and success envelopes with a missing or null result end with
`workers.upload_create_only_outcome_uncertain` and `retryable:false`; read back
the Worker and reconcile provider evidence before deciding whether to continue
or claim creation.

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

### Bot Management permission preflight and 403 recovery

The zone Bot Management update operation requires the complete permission pair
`Bot Management Write` and `Zone Settings Write`. Do not infer readiness from
one member of the pair or from a successful token-verification status alone.

Before requesting a mutation confirmation token:

1. Read the account-owned token with `account_api_tokens action=get`.
2. Pass the fresh permission-group names as `api_mutate.token_permissions` on
   the Bot Management update dry-run.
3. If the response names missing permissions, run its
   `account_api_token_permission_plan` call, review the preserved-policy delta,
   then run the returned `account_api_tokens` update as dry-run followed by one
   exact confirmation-gated apply.
4. Read the token back and confirm both permission names are present.
5. Rerun the original Bot Management mutation dry-run, apply it once with that
   new confirmation token, then use
   `bot-management-for-a-zone-get-config` through `api_read` for authoritative
   configuration readback.

A first HTTP 403, including Cloudflare error 10000, is a recoverable
permission/preflight signal, not proof that interactive authentication is
required, and is not a goal-blocking condition. Do not switch to a dashboard,
remote desktop/noVNC, or human authentication after that first response.
Escalate to a person only when account-token inspection or the guarded update
path is positively unavailable through the MCP, or when exact provider evidence
proves a distinct external authority requirement. Record the specific
unavailable tool or provider authority; do not report a generic auth blocker.

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

The R2 helpers use S3-compatible credentials, not the general Cloudflare API
token. A `403 Forbidden` on an existing object usually means the configured R2
token does not include that bucket. Treat the configured R2 access-key id as
the account-owned token id and inspect it without exposing the secret:

```text
tools/call name=account_api_tokens arguments='{
  "action":"get",
  "token_id":"<configured-r2-access-key-id>"
}'
```

If the bucket is absent from `policies[].resources`, preserve every existing
resource and the `Workers R2 Storage Bucket Item Read` permission, add only the
missing bucket resource, then use `account_api_tokens action=update` with the
normal dry-run and confirmation-token flow. Updating that policy retains the
existing S3 key material, so no secret rotation or MCP restart is required.
Re-run both `r2_inspect_object` and a bounded `r2_get_object` byte-range after
the change. Do not broaden the token to write access merely to solve a read
failure.

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
