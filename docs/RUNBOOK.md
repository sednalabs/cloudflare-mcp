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
- The current HTTP auth surface is Bearer-only. Ordinary Bearer tokens remain
  supported, but any token carrying a `cnf` confirmation claim is rejected as
  sender-constrained rather than accepted without proof of possession. Do not
  present DPoP-bound tokens to this surface; DPoP is not implemented here.
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

## Exact D1 row-write lifecycle

Before exposing `d1_execute_write`, configure both the shared private
`CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT` and the comma-separated canonical
lowercase `CLOUDFLARE_MCP_D1_RESERVED_RELATIONS`. The latter is operator
authority and must include every protected application root; callers cannot
override it.

Live DML custody uses only the fixed `dml-custody-v1` target child. Its
canonical marker binds the target and layout digest; claimants live at
`claimant/<namespace>/<aa>/<bb>/<identity-digest>.json` and attempts at
`attempt/<aa>/<bb>/<binding-digest>.json`. Flat, mixed, linked, misplaced,
unknown, non-private, or malformed artifacts fail closed. The held target guard
audits only affected leaves on the hot path. Before creating any claimant in a
set, every affected leaf must have capacity for all missing permanent entries
plus one CAS scratch entry; attempt creation applies the same reservation.
Exact `.next.<record-digest>.<predecessor-digest>.<successor-digest>.json`
scratch is crash-reconcilable. Stable leaf audit permits at most one scratch
per record, rederives its predecessor from the permanent incumbent and its
successor from canonical scratch bytes, and rejects duplicate, stale,
malformed, linked, or mismatched siblings. CAS consumes the audited file
identity, renames it, and re-audits for zero remaining scratch plus exact
successor readback. The separately bounded stable
complete audit traverses every shard, verifies canonical placement and
rederives each claimant intent, every physically complete three-namespace
claimant-set digest, and every attempt binding. It then proves the relation in
both directions: each attempt requires exactly one complete exact `Bound` set,
and each complete or partial claimant set is classified against its referenced
attempt. Every canonical attempt independently rederives its phase from the
durable reservation, ambiguity, provider-assertion, readback-assertion, and
terminal-outcome product instead of trusting the stored phase label or
claimant presence. The receipt counts `prepared`, `dispatch_reserved`,
`reconciliation_required`, `terminal_applied`, and `terminal_not_applied`
attempts and binds the complete phase product into `audit_sha256`. Conflicting
bindings, duplicate namespaces, digest drift, malformed or aliased phase
bytes, or incorrect placement fails closed. A canonical attempt without its
complete exact set and a valid `Bound` set whose attempt is absent are explicit
reconciliation evidence; `Pending`, partial, and CAS-scratch products are also
`reconciliation_required`. A matched `Prepared`, `DispatchReserved`, or
`ReconciliationRequired` attempt remains unresolved and makes the full audit
reconciliation-required; only the existing governed `TerminalApplied` and
`TerminalNotApplied` phases can participate in a clean target-wide product.
The fixed aggregate receipt reports matched and
unmatched attempts plus matched, unmatched, orphan, complete, and incomplete
set counts, the five phase counts, and always declares
`provider_dispatch_authority=none`. Target-wide authority accepts only a clean
fixed-budget projection of that receipt: no Pending claimant, CAS scratch,
partial/orphan/unmatched set, unmatched attempt, malformed artifact, or
nonterminal attempt, or nonfixed layout/budget identity. Fresh migration lease acquisition first
installs or validates the fixed empty layout under the already-held permanent
target guard, then runs that proof before creating `active.lease.json`. It
persists the exact audit identity in the lease payload and re-runs it at
provider, receipt-persistence, restoration, and retirement boundaries. Because
terminal receipts bind `lease_payload_sha256`, they also bind the exact
complete-audit identity.
Curated database rename and delete derive one canonical eight-step static plan:
validate exact intent, ensure fixed local custody, authorize a clean complete
audit before fresh state, install canonical `Prepared` custody, authorize and
immediately revalidate its exact owner, compare-and-exchange once to
`DispatchReserved`, issue at most one provider request, then retain one
post-provider custody product.

The target-wide custody boundary rederives the exact typed current eight-step
plan and consent from canonical target/change/reason facts and rejects any
detached or version-drifted plan, binding, digest, or token even when recomputed
self-consistently. It hashes pairwise-distinct opaque operation,
execution-attempt, and provider-request identifiers and binds them to the exact
current-version consent token, complete static plan, normalized target/change,
and optional reason. Consent and operation versions are persisted in state,
binding hashes, receipts, and replay equality. Under the held target guard it
first asserts the exact captured target before any local namespace access, then
reuses the fixed sharded layout and the
three create-once claimant namespaces, converges an exact partial claimant set,
seals the complete set to one attempt binding, and create-once installs only a
canonical `Prepared` attempt. Exact replay returns the incumbent bytes; changed,
cross-operation, malformed, noncanonical, unsafe, linked, or over-capacity
evidence fails closed with zero provider calls. `Prepared` is not dispatch
authority. A separate internal owner-aware revalidation now accepts only one
canonical target-wide `Prepared` attempt with its exact three `Bound`
claimants, while every other attempt in the stable complete audit is terminal.
It binds the current consent/operation versions, canonical target, plan,
operation/attempt/provider-request hashes, attempt and claimant-set bindings,
and complete surrounding-audit identity into an aggregate-only authorization.
The authorization scope is only the local
`Prepared -> DispatchReserved` compare-and-exchange and explicitly retains
`provider_dispatch_authority=none`; immediately before that persistence
boundary, the exact product is recomputed and compared. The global
target-wide audit authority remains unchanged and rejects any `Prepared`,
`DispatchReserved`, or `ReconciliationRequired` attempt.

Before acquiring the target guard, the live boundary independently rederives
the complete current plan and extracts the closed rename or delete request from
that exact product. There is no separate caller-selected provider-operation
input. A plan/request mismatch or impossible extraction fails while layout is
still `unobserved`, reservation is `not_installed`, and provider calls remain
zero.

The owner-aware negative matrix rejects absent/partial claimants or attempts,
multiple or foreign Prepared owners, nonterminal surroundings, changed complete
audit identity, malformed/noncanonical/contradictory restored bytes, unknown or
misplaced artifacts, unsafe modes or links, CAS scratch, and capacity/budget
failure. Both claimant-first and attempt-first installation orders authorize
only after exact convergence; exact replay converges. This policy stays in the
Cloudflare D1 adapter because it has one D1 caller. It reuses the toolkit's
provider-neutral private-artifact primitives, but does not uplift a D1 lifecycle
contract without a second independent caller. The routed lifecycle performs
exactly one `Prepared -> DispatchReserved` CAS and exact readback, revalidates
the held target guard, then permits at most one no-redirect Cloudflare request
carrying the preallocated provider-request identity. Exact replay of
`DispatchReserved`, `Acknowledged`, or `ReconciliationRequired` custody never
redispatches. Reserved or reconciliation replay enters only the two-read
recovery boundary; terminal replay performs zero provider calls.

Every dry run returns the full plan, `intended_plan_sha256`, a versioned
`consent_binding`, and `required_confirmation_token`. The consent binding
contains the normalized account/database target, operation and operation
version, normalized requested change, optional reason, plan digest, and the
complete plan. Any change to those values changes the token. Dry-run
`execution_evidence` keeps layout `unobserved`, audit and revalidation
unmaterialized, durable reservation `not_installed`, and local/provider
effects at zero. Dry-run itself never installs custody or contacts the provider.

Every live rename/delete call first recomputes that binding. Missing, altered,
stale, cross-target, cross-operation, changed-intent, or changed-reason tokens
return `confirmation_required` before target-guard or provider access. An
exact token enters the guarded lifecycle. Any target guard, layout, audit,
identity, version, capacity, owner-revalidation, or reservation-CAS failure
before dispatch reports zero provider calls and does not cross the provider
boundary. `Prepared` authority alone never permits dispatch.

Rename/delete use one D1-database-only client lifecycle after durable
reservation. Its strict response-envelope contract is one bounded,
duplicate-free exact Cloudflare
envelope with literal `success=true`, empty `errors`, unique exact
ResponseInfo `messages`, and the operation-specific result. ResponseInfo codes
are JSON unsigned integers at least 1000; optional-field presence participates
in uniqueness, while object property order does not. Rename requires a non-null
D1 database result. Delete accepts absent/null as `{}` and returns a present
non-null value through the existing `serde_json::Value` interface. A valid
acknowledgement is immediately retained as aggregate-only `Acknowledged`
custody. Transport loss, body-read failure, malformed or contradictory
envelopes, and HTTP/provider rejection are immediately retained as
`ReconciliationRequired` when the local CAS remains provable. If post-provider
derivation, CAS, or readback is ambiguous, the response still retains bounded
digest/lifecycle evidence, forbids retry, and requires operator reconciliation.
Neither immediate outcome is terminal effect proof. Repeating the exact
consented call performs two strict authenticated no-redirect GETs. Matching
rename metadata proves applied only when the requested name is present and
otherwise proves not applied; a missing rename target remains unresolved.
Matching delete 404 evidence proves applied, while matching exact present
metadata proves not applied. Only then may one predecessor-bound CAS install
immutable terminal custody. Any unstable, malformed, redirected, missing,
contradictory, or insufficient result remains reconciliation-required.

The complete audit pass has a fixed, versioned DML-specific global budget: at
most 16,384 canonical leaves, 65,536 physical leaf artifacts, and 268,435,456
total artifact payload bytes. It reserves leaf capacity before descent, artifact
capacity before any payload read, and remaining bytes from held metadata before
each read. Every cross-shard retained collection is bounded by the same
artifact ceiling. The stable second pass starts with a fresh budget and must
independently reproduce the first receipt. Budget exhaustion fails before an
aggregate receipt, audit digest, or authority claim exists and returns no path,
identity, or payload detail. The fixed layout marker is separately bounded and
validated by the layout snapshot; these global counts cover the variable leaf
graph. The undeployed flat candidate layout has no compatibility read or
migration path.

Dry-run the exact target, SQL bytes, parameters, row cap, and three
pairwise-distinct opaque operation/attempt/provider-request identities. The dry
run performs two read-only primary catalog observations and returns the exact
composition digest; its mutation plan contains no local or provider side-effect
step. A live call must repeat every byte and identity and supply that digest.
Under the shared target guard, it first create-once installs three independent
`Pending` identity claimants bound to the exact caller plan. Physically present
malformed or conflicting claimants fail closed before catalog access; an exact
partial set is completed deterministically. After recomputing
catalog/graph/composition authority, live execution seals all three claimants
by exact compare-and-exchange to the one full attempt binding. No provider
dispatch is permitted until the complete `Bound` set is reread. It then durably
installs one create-once Prepared state and one DispatchReserved
compare-and-exchange before the only DML provider request. The live mutation
plan marks atomic layout/capacity preparation, claimant installation/sealing,
both attempt-custody writes, and
provider submission as side effects. It also
marks the required post-provider custody compare-and-exchange as a side effect:
authenticated acknowledgement records `ProviderAssertionRecorded`, while a
missing or ambiguous response records `Ambiguous`. Reached-phase evidence names
the installed successor and whether provider submission was attempted; dry-run
contains none of these write or submission steps. If successor derivation or
its compare-and-exchange fails after an attempted submission, require the
failure receipt to retain aggregate response digest/size and provider lifecycle,
classify derivation failure as `not_installed` or compare-and-exchange failure
as `failed_or_unproven`, leave successor installation unconfirmed, and keep
reconciliation-only no-retry authority without returning response body text or
raw identities. Audit
outcome is closed to `planned`, `error`, or `reconciliation_required`; a
provider acknowledgement or response-loss ambiguity remains
`reconciliation_required`, not terminal success.
If guard custody changes after the two catalog reads but before Prepared
creation, return a complete blocked lifecycle receipt with two provider reads,
zero provider mutations, the complete live plan, and explicit false flags for
Prepared, DispatchReserved, and provider submission.
The pre-provider classifier uses a capped lexical token stream. An UPSERT must
contain one balanced top-level `ON CONFLICT ... DO UPDATE SET` action; tabs,
newlines, repeated ASCII whitespace, and keyword case are equivalent. String
literals cannot create keyword authority. Boundary normalization removes only
ASCII whitespace; non-ASCII space, separator, control, or BOM bytes outside a
string literal remain syntax and fail closed, including after a semicolon.
Comments remain unsupported, and
`DO NOTHING`, truncated or duplicate actions, unbalanced/deep parentheses,
token exhaustion, and unknown conflict forms stop before any catalog read.
Only plain `INSERT` may carry that UPSERT action. `INSERT OR REPLACE` and
`REPLACE` fail closed on every top-level conflict/action suffix so an UPDATE
effect cannot be omitted from the primitive product. Unquoted relations start
with lowercase ASCII and retain lowercase ASCII, digits, `_`, and `$` as one
exact identity; for example, `safe$protected` never degrades to `safe`.
This exact `UpsertDoUpdate` form exposes both INSERT and UPDATE primitives to
the reserved-relation graph, including UPDATE edges that cascade into a
configured reserved relation.
Fresh dry-run and live observation identities are expected to differ. The
composition validates both complete observation receipts but hashes their
stable catalog-authority projection, so an unchanged normalized snapshot and
graph reproduce the approval while any semantic catalog drift rejects it.

Never replay an incumbent attempt. A provider acknowledgement, including a
valid zero-change acknowledgement, remains retained for effect-specific
readback and terminal finalization. Transport loss, response ambiguity,
provider rejection, storage drift, or exact replay is reconciliation-only and
keeps `automatic_retry_permitted=false`; the durable post-provider successor is
custody for reconciliation, never authority to submit again. Validate this lifecycle only with
synthetic local files and mock provider endpoints; do not use a live D1 target.

## First-ledger bootstrap for an empty D1 target

Use `d1_bootstrap_migration_ledger` only for a separately selected database
that is intended to be empty before its first migration. Do not use it to add a
ledger to an existing application database, repair a partial initialization,
or bypass `d1_apply_migration_manifest`.

1. Configure `CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT` to the same trusted,
   private Linux custody root used by manifest apply.
2. Call the bootstrap with `dry_run=true` and the exact account, database, and
   optional canonical ledger-table identifier. Confirm that the response
   reports two provider reads, zero mutations, `target_inventory.state=empty`,
   a lowercase `plan_sha256`, two chronological one-attempt
   `provider_read_lifecycle` entries, and matching exact-body
   `response_evidence`.
3. Independently confirm that this is the intended empty target. Approval of a
   manifest apply, an account default, or a similarly named database is not
   bootstrap approval.
4. Call the same tool live with the exact dry-run `plan_sha256`. The tool
   repeats the stable primary empty preflight under the account/database target
   lease and issues at most one non-idempotent canonical initializer.
5. Treat success as proven only when the response reports one provider
   mutation, the canonical ledger as the only non-internal schema object, an
   empty filename ledger, and released custody. A DDL acknowledgement may
   report zero changed rows, but it must report primary service,
   `changed_db=true`, and typed non-negative counts before the stable post-state
   can authorize success. Continue with a separate `d1_apply_migration_manifest`
   dry-run; bootstrap approval never approves migration SQL.

If the initializer response is lost or malformed, do not retry. The tool makes
bounded read-only reconciliation calls with no redirects or adapter retries,
retains custody when it can prove the local chain, and reports the single
mutation attempt plus exact physical read accounting. HTTP/auth/rate-limit/5xx,
transport, truncated, oversized, malformed, invalid-UTF-8, non-primary, and
unstable evidence stays fail-closed. Builder/config failures remain
pre-dispatch with zero calls. Confirm every lifecycle/response entry retains
its exact lifecycle window, phase, and query digest, and every nested provider
cause says `retryable=false` with reconciliation-only guidance while omitting
provider response text. Escalate that exact evidence to
the governed reconciliation path. A canonical empty ledger observed afterward
does not prove whether this call created it, so it is not permission to replay.

Every new bootstrap lease carries the
`bootstrap-initializer-attempt-marker-v1` protocol. Immediately before the one
initializer dispatch, the coordinator durably creates an exact attempt receipt
under the held target guard. A failure before that receipt exists is therefore
distinguishable from every attempted or ambiguous initializer outcome.

### Retire bootstrap custody after a proven zero-dispatch failure

Use `d1_abort_bootstrap_migration_ledger` only when a bootstrap result retained
custody with `provider_outcome=not_dispatched` and zero provider mutations, such
as a failed active-to-retiring release after the under-custody empty-target
proof. Supply the exact target, ledger table, bootstrap plan, lease nonce and
payload digest plus distinct terminal request and attempt SHA-256 identities.

1. Call the abort tool with `dry_run=true`. It performs no provider access. It
   accepts only marker-aware bootstrap lease bytes and proves the exact
   initializer-attempt receipt is stably absent under the held guard. Legacy
   custody, a present marker, malformed or contradictory marker evidence,
   absent/conflicting lease evidence, or retiring/retired custody without the
   exact terminal receipt fails closed.
2. Independently approve the returned terminal-plan digest, then repeat with
   `dry_run=false` and that exact digest. The tool creates a canonical
   `not_committed` receipt, re-proves marker absence, and moves custody through
   active -> retiring -> `retired.<nonce>.lease.json` with directory sync at
   each boundary.
3. Require `bootstrap_zero_dispatch_abort_complete`,
   `provider_initializer_dispatches=0`, `provider_calls=0`,
   `provider_mutations=0`, and verified retired custody. Exact replay returns
   the same terminal receipt with zero mutations. Changed request/attempt or
   plan authority conflicts with the incumbent receipt.

Never use this path after an initializer attempt. A durable attempt marker is
permanent no-retry evidence even when transport never returned a response. Use
the read-only bootstrap reconciler and normal bootstrap finalizer for that
state. After a successful zero-dispatch retirement, any later bootstrap is a
new operation requiring a fresh empty-target dry run and approval.

### Recover retained bootstrap custody

This recovery is bootstrap-specific. Never substitute an empty migration
manifest and never issue the initializer again.

1. Preserve the exact `active.lease.json` or `retiring.lease.json` and record
   the original bootstrap result's plan, nonce, payload digest, account,
   database, and migrations-table identity.
2. Call `d1_reconcile_bootstrap_migration_ledger` with those exact fields. It
   locks and validates the existing `migration-ledger-bootstrap-v1` custody,
   then makes two stable primary proof windows. Each window contains two schema
   inventory reads and two empty-ledger reads. Every read is one HTTP attempt,
   never follows a redirect, and records exact response-byte digest, size, and
   lifecycle evidence. A successful response therefore reports eight actual
   provider dispatches, zero provider mutations, zero local namespace mutations,
   and four approval products: reconciliation plan, initializer
   authority, query authority, and canonical snapshot digests.
3. Stop on any nonterminal product. Physical ledger absence or any non-ledger
   object is `conflicting`; a non-empty ledger is also conflicting. Malformed,
   non-primary, unreadable, unstable, or custody-drifted evidence is `unknown`.
   Every state keeps initializer retry forbidden and leaves custody in place.
4. Record the four successful reconciliation digests and choose two distinct
   operator-controlled lowercase SHA-256 request and attempt identities. Call
   `d1_finalize_bootstrap_migration_ledger` with `dry_run=true`; independently
   approve the returned terminal-plan digest.
5. Repeat with `dry_run=false` and the exact approved terminal plan. The tool
   repeats the eight-read proof, performs one additional four-read proof before
   creating the canonical private receipt, performs another four-read proof
   before retirement, and issues no provider write. Only then may it durably
   move custody from active to retiring to `retired.<nonce>.lease.json`. If
   custody changes during either refresh, require `lease_retained=null` and
   `retained_evidence_unverified`; after receipt creation the response must also
   report that receipt and its one local namespace mutation without retiring it.
6. Require `bootstrap_terminal_complete`, verified retired custody, the exact
   receipt digest, `provider_mutations=0`, and truthful local mutation counts.
   Treat the final descriptor-bound readback as current receipt authority: a
   failed readback must report its observed true/false/null receipt state, not
   merely the earlier successful creation event.
   An exact completed replay validates the receipt and retirement with zero
   provider calls. A receipt without matching provider proof, or retirement
   without the exact receipt, is a blocker rather than cleanup authority.

The only terminal provider product is the exact schema produced by the
approved canonical initializer, with that ledger as the sole application-owned
object and zero ledger rows. This proves current convergence, not which caller
created it. General manifest reconciliation remains a separate authority and
cannot reconcile or retire bootstrap-family custody.

## Exact-byte D1 migration manifests

### Shared existing-target mutation guard

Configure `CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT` for every MCP process that
can run curated D1 row-write, target-wide rename/delete, bootstrap, or manifest
mutation.
The name is retained for compatibility, but the directory is now the shared
account/database target-guard root. The active `d1_execute_write` MCP path
acquires the same permanent `guard.lock` as bootstrap and manifest apply
immediately before provider dispatch. A same-target contention or retained
active/retiring lease is a stop condition; a different database target is
independent. A guard failure reports the invoked active curated tool as its
operation and zero provider calls/mutations; preserve that caller-correlated
receipt when diagnosing the contention.

Fresh row-write, manifest, and bootstrap acquisition may create only the fixed
empty `dml-custody-v1` layout, under the already-held permanent target guard
and before any complete-audit authorization. Governed MCP rename/delete use an
eight-step consent plan; their previews record `ensure_d1_dml_custody_layout` as
`create_if_absent_at_live_guarded_execution`, `local_custody_only`, and
`provider_dispatch_authority=none`. Live execution later requires exact owner
authority and one durable reservation before its single permitted provider
request. The returned
`intended_plan_sha256` is stable across matching dry/live calls; runtime custody
facts appear only in `execution_evidence`. An existing layout must validate
exactly; a fresh successful ensure reports `created` with one local mutation,
while exact existing custody reports `already_present` with zero local
mutations. Ensure failure reports failed/unknown local-mutation state and zero
provider calls. Active guarded paths do not replace, flatten, or repair hostile
or partial evidence. If audit or revalidation fails after an active ensure, the
error preserves the observed local outcome while proving zero provider
dispatch. The lower-level `CloudflareClient` adapter remains distinct. Every
direct rename/delete caller must supply its own governed consent and durable
reservation/recovery wrapper before provider dispatch; that adapter capability
does not bypass the MCP lifecycle.
Retained-evidence reconciliation, terminal receipt persistence, rollback
restoration, and retirement require the layout to remain present and exact;
absence is evidence loss, not an empty/default state, and those paths create
nothing. Migration lease bytes carry the exact audit identity; recovery rejects
legacy, malformed, absent, or changed custody and re-audits current physical
custody under the held guard. Do not copy an audit digest between targets or
runs. Ordinary `d1_execute_write` remains leaf-scoped and does not pay for or
inherit this target-wide authority gate.

Generic `api_mutate` is not a fallback for an existing D1 target. Delete,
export, import, query/raw query, time-travel restore, full update and partial
update are denied before request construction. Use the curated guarded tool
where one exists; otherwise defer to a separately governed lifecycle. A future
restore/import/activation surface must compose this same complete-audit gate;
the current denial is not permission to bypass it. Always
copy account and database IDs exactly from Cloudflare. Existing D1 database IDs
must be canonical lowercase hyphenated UUIDs; uppercase, mixed-case, compact or
braced variants are aliases, not independent targets. Do not trim, recase,
encode or otherwise repair a rejected identity.

### Private SQL artifact and upload boundary

The reusable private-artifact boundary is intentionally lower-level than any D1
import workflow. Generic descriptor-bound read custody comes from the pinned
`mcp-toolkit-private-artifact` crate; the Cloudflare adapter retains the
non-empty SQL and stable D1 error-code contract. It opens a local SQL artifact
through held Linux descriptors,
applies the migration custody root/ancestor/owner/mode/hardlink policy, including
root-or-current-operator ownership for every external ancestor, hashes
the exact stable descriptor bytes, and re-proves the descriptor-to-path binding
before a later caller may upload those bytes.

The upload adapter requires the exact account and database context that produced
the D1 import-init response. It accepts only the corresponding canonical
Cloudflare R2 account hostname over HTTPS, never follows redirects, and disables
automatic HTTP retries. Errors
and receipts omit the local path, SQL, presigned URL, account ID, and database
ID. This boundary alone is not an operational import procedure and provides no
admission, retry, ingest, poll, reconciliation, or terminal authority.

The provider contract is documented by Cloudflare's
[D1 import API](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/import/)
and [R2 presigned URL guidance](https://developers.cloudflare.com/r2/api/s3/presigned-urls/).
The presigned hostname binds the account, while the initiating D1 request
context must independently bind the database; the URL alone is not database
authority.

Use `d1_apply_migration_manifest` for an approval-gated D1 migration family.
Never pass the reserved exact family `migration-ledger-bootstrap-v1` to this
generic tool or to generic reconciliation/finalization. Only the dedicated
bootstrap lifecycle owns that family; generic boundaries reject it before
provider access or local custody/receipt activity.

First run it with `dry_run=true`; retain the returned `plan_sha256`, which is
bound to the exact SQL bytes and current Wrangler ledger prefix. A live call
must submit that exact lowercase value, without whitespace or case changes, as
`approved_plan_sha256` and configure
`CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT` to a pre-created, operator-owned,
non-group/world-writable directory shared by every MCP process that can target
the database. Manifest names may be current Wrangler paths relative to
`migrations_dir`, including nested layouts such as `0001_init/migration.sql`.
Supply them in Wrangler's segment-wise numeric order with lexical tie-breaking;
absolute, backslash, empty, dot, traversal, and NUL path forms fail closed. On
Linux the root must be an absolute real directory owned by the
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

For the canonical UUID target-identity upgrade, do not reuse a root containing
any predecessor custody. Stop every predecessor write-capable MCP process,
preserve its old root without deleting or moving retained evidence, reconcile
any active or retiring operation through its governed recovery path, and
provision one new private empty `0700` root for all upgraded writers. On the
first canonical target guard, the upgraded MCP holds
`target-identity-v2.guard.lock`, exhaustively enumerates the root up to the
finite custody limit, creates the target's exact create-only
`target-identity-v2.<target-key-sha256>.receipt.json` registration, and creates
the exact `target-identity-v2.activation.json` marker only after the root was
proved empty before activation. After activation, every target must have its
matching canonical registration. A stable bounded audit validates the marker,
all registrations, all target directories, and every allowed custody entry;
that audit is repeated at guard/lease revalidation, provider, persistence, and
release boundaries.
Canonical incumbent directories are intentionally rejected along with alias,
active, retiring, retired, terminal, malformed, unreadable, symlink, and
over-limit evidence: predecessor payloads contain only a target hash and cannot
prove the UUID spelling that produced it. A failed activation does not clean up
or migrate evidence. Do not manually create the marker, reuse the blocked root,
or allow an older binary to open the activated root. Draining every predecessor
writer before cutover is an independent deployment prerequisite, not a
substitute for these runtime audits. This local activation has zero provider
calls; it does not itself approve a D1 mutation.
Rollback is also a whole-generation operation: drain every upgraded writer,
preserve the activated root without manual edits, and return all writers
together to the preserved predecessor root and predecessor binary generation.
Never run mixed roots or binary generations during cutover or rollback.

The exact-byte manifest boundary accepts at most 16 MiB of aggregate SQL and
moves the supplied manifest into validation without cloning its SQL strings.
Split a larger migration family before review rather than increasing this
operator-surface memory bound.

D1 already enforces foreign keys and runs migrations in an implicit
transaction, so it rejects attempts to enable them inside the submitted query.
See Cloudflare's
[D1 foreign-key guidance](https://developers.cloudflare.com/d1/sql-api/foreign-keys/).
If a reviewed source migration begins with the byte-exact text
`PRAGMA foreign_keys = ON;` and then two LF bytes, dry run preserves the raw
manifest authority and derives execution transform
`drop-leading-pragma-foreign-keys-on-v1`. Confirm the returned
`execution_manifest` contains the expected transform ID/version,
`executed_sql_sha256`, and `provider_statement_sha256` before approving the
version-2 `plan_sha256`. The executed provider SQL omits only that exact prefix;
the source SHA-256 never changes. Any variant, duplicate, embedded occurrence,
or empty transformed remainder is a pre-provider hard stop for a new dry-run or
apply. Retained read-only reconciliation continues to recognize an exact
predecessor version-1 plan under the existing effect-assertion grammar, but it
cannot authorize fresh execution. Untransformed manifests keep their existing
version-1 plan identity.

For retained custody, always supply the original source manifest and the exact
approved apply-plan digest. That digest commits the execution transform and is
carried by the lease payload, reconciliation relationship, terminal receipt,
finalization plan, and completed replay. Never reconstruct approval from the
executed SQL or edit the manifest to remove the pragma after an ambiguous
attempt; either change is conflicting evidence and must fail closed.

Every manifest-owned provider write uses its own one-attempt HTTP client. It
requests identity response encoding, never follows redirects, and consumes the
response as a stream capped at 16 MiB before UTF-8 or strict-envelope decoding.
A 307 or 308 is provider response evidence, never authority for a second POST.
Declared or streamed oversize, unsupported content encoding, read failure,
invalid UTF-8, malformed JSON, and contradictory envelopes after dispatch all
retain the exact write lifecycle and bounded body digest/size evidence when
available. Treat every such result as ambiguous: retain custody, reconcile,
and never replay the migration write automatically. A decoded HTTP 200 outer
envelope retains that same complete-body evidence through inner D1 result
validation; malformed, missing, or failed inner results remain one attempted
write with unknown outcome, not a replayable provider rejection.

On a live manifest call, the MCP first performs a read-only inspection of any
existing target custody. It never creates a target or guard during this step;
an active or retiring entry therefore stops a fresh caller before any provider
request. Only then, before a new lease or migration SQL, it performs two
primary-served readbacks of the configured migration-ledger authority. They
must agree and prove exactly one canonical ledger table with the supported
schema and no trigger targeting it. A missing, case-conflicting, wrong-type,
wrong-schema, malformed, non-primary, or unstable result is a hard stop: no
new local custody or provider write is created. This is intentionally separate
from the filename ledger prefix read, which cannot establish what a later
`INSERT INTO <ledger>` means.

Every filename-ledger read used by the dry plan, live preflight, post-apply
readback, or ambiguity reconciliation must itself be served by the D1 primary:
the single result set requires literal boolean `meta.served_by_primary=true`.
Missing, false, non-boolean, malformed, duplicate, or unstable evidence is not
a usable ledger and fails closed. The manifest client rejects duplicate JSON
keys before the result reaches either ledger parser.

After the governed lease and reviewed plan are bound, the MCP repeats that
stable authority proof immediately before every migration statement, then
revalidates its held local custody immediately before each dispatch. It repeats
the proof and custody revalidation again before successful terminal custody
release. This prevents a preflight result from becoming stale while local
plan/custody work is underway; a failure before the first write releases the
pre-write lease, while any failure after an acknowledged write retains explicit
reconciliation custody and stops later provider mutations.

An `applied` response is stronger than a clean HTTP envelope or an empty D1
result array. Every provider result set for the migration write must explicitly
prove `meta.served_by_primary=true`, a boolean `meta.changed_db`, and typed
non-negative integer `changes` and `rows_written` counts. A result with
`changed_db=false` is valid only when both counts are zero. The complete
response must contain at least one `changed_db=true` result and have positive
aggregate changes and rows-written totals. The MCP then requires the stable
primary ledger readback to contain the complete manifest and repeats the
reserved-ledger authority proof before it can release custody. Missing,
replica-served, malformed, zero-total, or contradictory write metadata is
`reconciliation_required`: the lease is retained when its custody can still be
proved and the SQL is never retried.

A later invocation stops before provider I/O when it sees an active or
`retiring.lease.json` entry, including one that is malformed, a symlink or
non-regular. It must be resolved only through the governed recovery path,
never inferred stale or reclaimed. Normal terminal completion moves
the active file under the held guard to `retiring.lease.json`, synchronizes the
target directory, then records `retired.<nonce>.lease.json` without replacement
and synchronizes again. A failed synchronization restores the exact active
entry or leaves active/retiring evidence as an explicit blocker. A failed
creation is retained as
`aborted-create.<nonce>.lease.json`; production code never unlinks a lease file
or directory. The manifest tool never reopens a migration directory after
review and never retries an ambiguous provider write. It first performs stable
primary-ledger reconciliation and then revalidates the exact local custody
chain before saying the active target lease was retained. If that local custody
has been lost or is unverifiable, the result reports
`lease_retained=null` and
`custody_status=lost_or_unverifiable_after_ambiguous_apply`; it keeps the prior
identity only as historical reconciliation context, not as a claim that a local
blocker exists. That result still prohibits replay: the absence of a local lease
file is never evidence that another process or operator may reapply SQL. A
matching ledger filename is only
an observation: it does not attest to the reviewed SQL bytes or complete
provider transaction, and therefore never authorizes lease release after an
ambiguous apply. This guarantee is limited to a trusted Linux filesystem that
supports working `renameat2(RENAME_NOREPLACE)`, directory `fsync`, and advisory
file locks. It is a shared-filesystem lease, not a Cloudflare-distributed lock;
cross-host or other shared-filesystem semantics require separate proof.
Separate provider/distributed coordination remains required when MCP instances
do not share that root. The product-neutral governed recovery path remains
required for retained, malformed, or tampered evidence. Non-Linux installations or
unsupported filesystems fail closed before provider I/O.

Terminal reconciliation never treats a local receipt write failure as proof that
no local mutation occurred. If the descriptor-bound receipt can be read back as
the exact receipt, the result reports it as persisted with one local namespace
mutation; if absence is proved it reports zero; otherwise both fields are
`null`. That receipt and namespace result is accepted only after a stable
descriptor-bound re-read before and after the receipt check; an altered,
missing, or uninspectable receipt makes both authority claims unknown. The
provider-call count covers only completed provider reads, never local receipt
storage. Likewise, a failure while moving active evidence through `retiring` to
`retired` reports the re-read current custody namespace and the exact completed
rename count: one for active-to-retiring and two once the terminal retired name
exists. Active retention is `lease_retained=true`, terminal retirement is
`lease_retained=false`, and retiring or unverifiable custody is `null`. None of
these outcomes authorizes replay.

### Read-only retained-manifest reconciliation

When an ambiguous apply retains `active.lease.json` or a failed terminal move
leaves `retiring.lease.json`, use `d1_reconcile_migration_manifest`; do not run
the apply tool again. Supply the same complete exact-byte manifest and the
reported approved-plan, nonce, and payload digests. Also supply ordered,
bounded `state_expectations` for every manifest prefix from zero through the
full manifest; a selected or partial prefix set is not accepted. Each state
names the exact `sqlite_master` object type/name/table and SQL digest, complete
`table_xinfo` rows, and complete foreign-key definitions for every declared
table. The tool independently derives every CREATE target at every prefix and
requires exact agreement, so a caller cannot omit a created table or index and
obtain convergence; the extended assertion applies the same rule to views and
triggers.

Select one explicit built-in effect assertion:

- `effect_assertion_id=schema_create_only_v1` remains the backward-compatible
  table/index contract and still rejects views and triggers.
- `effect_assertion_id=schema_create_tables_indexes_views_triggers_v1` adds
  versioned `CREATE VIEW` and `CREATE TRIGGER` classification. Each prefix must
  name every view as `type=view`, `name=<view>`, `table_name=<view>` and every
  trigger as `type=trigger`, `name=<trigger>`, `table_name=<parent table>`, with
  the exact `sqlite_master.sql` SHA-256. The trigger parent table must exist in
  that selected prefix. Only physical tables receive `table_xinfo`,
  `foreign_key_list`, and `foreign_key_check` expectations; views and triggers
  remain covered by the complete exact `sqlite_master` union.
- `effect_assertion_id=schema_create_objects_additive_v1` preserves that full
  CREATE-object proof and additionally classifies at most one canonical
  unqualified `ALTER TABLE <parent> ADD [COLUMN] <column> <type>` per manifest
  entry. The bounded column definition may add `NOT NULL`, one literal
  `DEFAULT` (`NULL`, signed integer, or quoted string), and one trailing
  `CHECK`, in that order when present. CHECK expressions are capped by token
  count, nesting depth, literal size, and IN-list length; they may reference only
  the added column through `IS NULL`, literal equality, a literal `IN` list, and
  the pure `length(column)` or
  `substr(column, positive_integer, positive_integer)` forms joined by
  `AND`/`OR`. Subqueries, other-column reads, unknown functions/operators,
  `REFERENCES`, `UNIQUE`, `PRIMARY KEY`, `COLLATE`, `GENERATED`, compound types,
  quoted/schema-qualified identities, and every other ALTER form are rejected.
  The parent must be present in the baseline or a strictly earlier prefix.
  Every transition must preserve the complete ordered prior
  `table_xinfo` and foreign-key state, append exactly one matching column, and
  bind the changed parent to a distinct reviewed `sqlite_master.sql` digest.
  The assertion also accepts exactly `PRAGMA foreign_keys = ON` as semantic
  migration intent. It does not execute caller SQL or claim that the provider
  connection retained PRAGMA state; proof remains the fixed read-only schema
  and foreign-key snapshot.
- `effect_assertion_id=schema_create_objects_additive_seed_rows_v1` extends the
  additive assertion with one canonical top-level seed INSERT per
  manifest-created target. Require plain unqualified table/column identifiers,
  explicit columns, bounded literal `VALUES` tuples, CREATE-before-seed, and
  seed-before-trigger ordering across the complete manifest. Reject every
  classified `CREATE ... IF NOT EXISTS`; seed authority requires an actual
  unconditional creation. Add the exact
  cumulative `seed_tables` summary to every prefix expectation: target, ordered
  columns, row count, and local row-set SHA-256. Treat ASCII case variants as
  one SQLite CREATE, ALTER, index, trigger, and seed target while retaining the
  reviewed `CREATE TABLE` spelling in expectations and fixed queries. Use the
  deterministic first-encountered manifest parent spelling for baseline tables
  not created by this manifest when ALTER/index/trigger parents vary only by
  SQLite ASCII case. Keep provider and expectation spelling unchanged in the
  selected fixed proof. Permit only identity-stable affinity pairs: for
  non-STRICT tables, TEXT literals on
  TEXT/BLOB columns and INTEGER literals on INTEGER/NUMERIC/BLOB columns; for
  STRICT tables, TEXT literals on exact TEXT columns and INTEGER literals on
  exact INT/INTEGER columns. Reject STRICT BLOB seeds before custody/provider
  access.
  Every assertion performs one primary-current prefix-selection read followed
  by two identical complete primary-current reads. Each complete read covers
  the bounded full-manifest `sqlite_master` object union, so premature future
  objects remain visible and contradictory, while table-valued `table_xinfo`,
  `foreign_key_list`, and `foreign_key_check` statements cover only the exact
  physical tables in the selected prefix. A prefix before a future table is
  created therefore never probes that absent table.
  Match schema-object membership under SQLite ASCII `NOCASE`, retain exact
  observed spelling and canonical type/name ordering, and reject aliases or
  conflicting spellings.
  Seed-row SELECTs remain selected-prefix and existence-aware. The full-manifest
  seed registry must prove three distinct prefix states: no seed-row SELECT from
  a table before CREATE, an exact zero-row table projection after CREATE and
  before INSERT without depending on columns added by a later prefix, and the
  exact typed row set at or after INSERT. Any row in the zero-row window must
  fail on the first complete proof with two total provider reads and zero
  mutations.
  Terminal dry run and live finalization must rederive and repeat that same
  selected-prefix proof. Require each complete proof ledger to equal the exact
  initial selected ledger, then separately require the two complete snapshots
  to be canonically equal. An equal pair at a different prefix is a
  reconciliation contradiction, not authority to reselect. Record only the
  aggregate-safe `selection_binding` query/ledger digests and selected prefix;
  do not copy raw provider rows. Parse every provider response locally, then
  freshly revalidate retained lease custody before reporting either the parsed
  snapshot or a parse failure as verified custody. Otherwise verify three
  provider reads, zero provider mutations, exact aggregate seed summaries, and
  no raw seed values in the response. Any ambiguity or mismatch remains
  reconciliation-required.
  The predecessor assertions do not accept top-level INSERT.
- Use the distinct
  `effect_assertion_id=schema_create_objects_additive_seed_rows_v2` only when a
  reviewed manifest contains canonical SQL `NULL` seed literals. Version 1
  remains closed to TEXT and INTEGER and retains its existing query, hash,
  receipt, and replay bytes. Version 2 adds NULL as a third typed literal,
  hashes `{"storage_class":"null","value":null}` inside a version-2 row-set
  proof, and requires every NULL target column to be nullable in reviewed
  `table_xinfo` and not an `INTEGER PRIMARY KEY` column in a rowid table, where
  SQLite would replace NULL with a generated rowid. Reject a `null` storage
  class with any non-null value, any
  non-NULL storage class with a JSON null value, and NULL against a `NOT NULL`
  column before terminal authority. Keep the v2 assertion ID unchanged through
  reconciliation, terminal dry run, live finalization, durable receipt, and
  completed replay. This assertion does not change provider migration-write or
  PRAGMA transmission behavior; treat that as a separate execution boundary.

The successful response identifies that same closed scope without flattening
the broader assertions back to the legacy label: `effect_assertion.scope`
reports `schema_create_only`, `schema_create_tables_indexes_views_triggers`, or
`schema_create_objects_additive`, or
`schema_create_objects_additive_seed_rows`, or
`schema_create_objects_additive_seed_rows_with_nulls` respectively, alongside the complete
allowed `schema_object_types` array.

For every assertion, the configured `migrations_table` is a reserved schema
identifier under SQLite ASCII case-insensitive matching. A manifest must not
create an object with that name, create an index or trigger on that table, or
use additive ALTER against it. Every accepted trigger contributes bounded
lexical evidence from the complete post-parent header (including `WHEN`) and
body: each word, quoted identifier, and string-literal value is retained, while
symbols carry no value. Any exact ASCII-case-insensitive collision fails
closed, including a string literal; longer unrelated token values remain valid.
This is rejected before expectation validation, custody
inspection, or provider access so an injected ledger INSERT cannot activate
manifest-defined behavior.

The successful response names the selected assertion and its exact object-type
scope. That ID is also part of the reconciliation-plan digest, terminal-plan
digest, version-2 durable receipt, and exact replay. Never change it between
approval and finalization, even when both assertions derive identical state for
a table/index-only manifest.

Receipt reads are deliberately dual-version while writes are version 2 only.
An exact canonical predecessor version-1 receipt has its original field set and
is mapped exclusively to `schema_create_only_v1`; it can resume active or
retiring custody and replay a completed retirement. It never attests the
extended assertion. Unknown fields, duplicate keys, malformed/noncanonical
bytes, or an attempt to pair version 1 with the extended assertion fail closed
before provider access. A version-2 receipt can bind a historical legacy-v1 or
historical-v2 full-union plan when terminal finalization promotes existing
active evidence, or the new scoped-v3 plan for a fresh reconciliation. Resume
and replay preserve that receipt-bound plan family rather than inferring query
chronology from the receipt schema version.

Terminal query compatibility is independently evidence-bound. Before provider
access, the finalizer independently recomputes the legacy-v1 full-union,
historical-v2 effect-assertion full-union, and scoped-v3 selected-prefix plan
families and requires exactly one to match
`expected_reconciliation_plan_sha256`. Only then must the exact approved
`expected_query_sha256` and expected current prefix reproduce that family's
constructor. Equal query digests do not change the selected chronology.
Unknown, ambiguous, or plan/query-inconsistent combinations fail with zero
provider calls. The predecessor non-seed form preserves its
historical two complete reads without a selection call; the predecessor seed
form preserves its historical selection plus two complete reads. This path is
only for reproducing already-approved active/retiring evidence and durable
receipts. New read-only reconciliation always emits the scoped-v3
selected-prefix form with explicit `query_chronology=selected_prefix_v1`.

Completed-retirement replay is not receipt-only lookup. Before returning the
zero-provider success, the terminal boundary reclassifies the supplied manifest,
validates the complete typed expectations, and locally recomputes the applicable
legacy-v1, historical-v2 full-union, or scoped-v3 reconciliation-plan digest.
Changed manifest names or bytes, expectation objects/tables, prefixes, or
assertion scope therefore cannot borrow an incumbent receipt.

The extended classifier keeps an entire trigger body together across internal
semicolons and nested `CASE ... END`, then accepts only bounded canonical
trigger identities, a supported event/header, and semicolon-terminated
`INSERT`, `UPDATE`, `DELETE`, or `SELECT` body statements. It rejects malformed
or unclosed quotes/comments/bodies, `TEMP`/`TEMPORARY`, schema-qualified names,
reused identities, and top-level DML. The two CREATE-only assertions refuse
arbitrary DML, ALTER, DROP, PRAGMA, virtual tables, `CREATE TABLE AS SELECT`,
`CREATE TABLE AS VALUES`, and other data-producing or unclassified CREATE
effects. The additive assertion refuses those same effects except for its exact
ADD COLUMN and foreign-keys-on forms; a caller assertion is not proof. An
effect capability gap means retain the lease and add
a purpose-built registry assertion/readback contract before continuing.

The tool opens the existing target and guard without creating entries, requires
exactly one active or retiring regular private evidence file, and holds the
guard across one prefix-selection read and two complete internally generated
read-only batches. It returns
`not_committed`, `partial_state_converged`, or `full_state_converged` only when
the current ledger is an exact manifest prefix, the retained approved plan
reconstructs uniquely from that prefix relationship, both canonical snapshots
match, and schema/FK proof is complete. These labels are documented atomic-state
inference, not proof of which provider attempt caused the state.

Every fixed result set carries a query-bound statement marker and a mandatory
sentinel row, including result sets with no data rows. Parsing requires the
exact marker, exact row shape, explicit success, empty errors, and—when
present—boolean `changed_db=false` plus integer `changes=0` and
`rows_written=0`. Every fixed result set in both batches must also carry exact
`meta.served_by_primary=true`; missing metadata or a false, null, non-boolean,
or mixed primary marker fails closed as contradictory evidence. Response bodies
are capped at 16 MiB from the HTTP stream; the adapter stops before buffering a
body beyond that bound.

Every reconciliation result reached after fixed-query construction includes a
`query_shape_receipt`. Its version and receipt digest bind the exact
`query_sha256` to aggregate statement counts and presence booleans for only the
ledger, schema catalog, table xinfo, foreign-key definition, foreign-key check,
and seed classes. It never contains SQL, schema/table names, paths, response
excerpts, or row data. Pre-query semantic failures return the field as null.
This output receipt does not alter the fixed query, its SHA-256, predecessor
plan reconstruction, or terminal receipt authority.

Before any strict D1 migration response object is converted to
`serde_json::Value`, the bounded raw body is decoded through the shared visitor
that rejects duplicate keys and more than 32 nested object/array containers.
The policy covers migration-write acknowledgements and reconciliation
success/error envelopes without changing generic Cloudflare response paths.
Rejected reconciliation evidence remains contradictory; a rejected
post-dispatch write acknowledgement remains ambiguous and retains custody. The
exact raw-body digest, byte count, HTTP status, and completed-read lifecycle are
captured first, and no key or value from the rejected body is returned.

The reconciliation HTTP client does not follow redirects. Interpret
`provider_read_lifecycle` in order: `pre_dispatch` means no provider call;
`attempted` with `not_received` means transport outcome without a response;
`received` plus `not_read`, `partially_read`, or `completely_read` records the
body boundary and exact captured HTTP status. A response-stream failure is
`not_read` when zero body bytes were accumulated and `partially_read` only
after at least one byte was accumulated. Preserve the status for invalid
UTF-8, malformed JSON, truncated streams, and oversized bodies. Treat 401,
403, 429, and every 5xx as unavailable and never retry the same attempt.
When a completely read authenticated HTTP error body is an exact, duplicate-
free Cloudflare error envelope, `provider_cause` may additionally expose only
an allowlisted numeric code and stable category: 7500 as `d1_error` or 10000 as
`authentication_error`. Provider messages are always discarded because they
may echo SQL or identifiers. Partial, malformed, oversized, duplicate-key,
over-depth, multi-error, non-allowlisted, or otherwise unexpected envelopes
retain generic HTTP classification and never expose provider body content. The
shared migration-envelope decoder applies its 32-container limit while parsing
both reconciliation and migration-write responses.

Interpret custody fields literally. Validation failures before custody lookup
return `lease_retained=null` and `custody_status=not_inspected`. Inspection
failures return `lease_retained=null` and `custody_status=inspection_failed`.
Both are before provider-adapter invocation and must explicitly return
`provider_calls=0` with `provider_read_lifecycle=[]`; missing fields are not
zero-call evidence. Adapter-local token/config failure is different: it records
one `pre_dispatch` lifecycle entry even though its provider-call count is zero.
Public semantic validation is ordered target, migrations table, manifest, then
migration family. Any failure there returns the complete fail-closed
reconciliation envelope with contradictory capability, uninspected custody,
null query digest, empty response/lifecycle evidence, and zero provider or
local mutations; it does not acquire lease custody or contact D1. JSON-RPC and
generated-schema parse failures remain MCP deserialization errors without a
structured reconciliation envelope because semantic tool execution has not
begun.
An omitted `account_id` with no configured default is part of target semantic
validation and must return that same zero-call envelope before any lease or D1
access.
Only a successfully acquired and revalidated retained lease may report
`lease_retained=true` and `custody_status=retained_evidence_verified`. If that
evidence drifts, conflicts, or fails revalidation around a provider read, the
result returns `lease_retained=null` and
`custody_status=retained_evidence_unverified`; do not infer that the named
evidence was removed. HTTP 429 and 5xx responses make provider evidence
unavailable and never authorize an automatic retry, including when the body
exceeds the streaming byte bound. Contradictory ledger, schema, plan, or
two-read evidence discovered after successful custody revalidation reports the
retained evidence as verified and includes the exact two provider calls; only
custody drift changes that status to unverified. `response_evidence` records
only captured response bodies; `provider_read_lifecycle` independently records
every invocation. Invocation position and count, not response-value equality,
determine that chronology: two byte-identical successful reads remain two
evidence and lifecycle entries, while reprocessing an already merged product
is idempotent. After one complete read, a second transport failure or
pre-dispatch adapter failure therefore leaves one response summary but two
chronological lifecycle entries. `provider_calls` counts only actual provider
attempts: it is `1` when that second invocation fails before dispatch and `2`
when the second invocation reaches transport. Standalone pre-dispatch failure
remains zero provider calls.
Revalidation runs after every
attempted provider call even when the provider returns an error. If provider
failure and custody drift coincide, retain the provider classification and
chronological response evidence while treating custody as unverified; the
`custody_cause` names the separate revalidation failure.

All read-only reconciliation results retain the lease and prohibit retry of the
same migration attempt. Record the query SHA-256, both bounded response-body
digests, expectation proof, canonical snapshot SHA-256, scope-completeness
fields, outcome/prefixes, and `reconciliation_plan_sha256`. Do not manually
rename or remove custody evidence.

### Terminal retained-manifest reconciliation

Use `d1_finalize_migration_reconciliation` only after the read-only result is
recorded. Supply every original manifest/expectation input plus the exact
reconciliation-plan, expectation-proof, query, snapshot, outcome and prefix
values, and preallocate distinct opaque request and attempt identities as
lowercase SHA-256 digests. First call with `dry_run=true`; it re-runs two
complete primary-current batches and returns `terminal_plan_sha256`. Record and
independently approve that exact digest before a live call. A digest derived
after the live read is not approval.

Before any custody inspection, confirm that original and current prefixes are
both bounded by the exact supplied manifest and apply this closed outcome
matrix:

- `not_committed`: current equals original;
- `partial_state_converged`: original is less than current and current is less
  than the manifest length;
- `full_state_converged`: original is less than current and current equals the
  manifest length.

No other outcome/prefix product may be planned, persisted, or replayed.
Canonical v1/v2 receipt readback cannot rederive manifest length, so it first
enforces the strongest independent subset: equal prefixes only for
`not_committed`, and strict growth for both converged outcomes. The terminal
request then rebinds that receipt to the supplied manifest and enforces the
complete matrix above. Canonical-but-contradictory restored evidence fails
before provider access or local namespace mutation in active, retiring, and
retired custody.

Reuse the exact same effect assertion in reconciliation, terminal dry run, and
live finalization. The terminal path derives and verifies the same complete
table/index/view/trigger inventory; it does not downgrade the assertion or
replace view/trigger `sqlite_master` proof with table PRAGMAs.

The live call requires `approved_terminal_plan_sha256` and follows this fixed
order while holding the permanent target guard:

1. Re-run the two-batch retained-manifest proof and require exact agreement
   with every approved evidence digest and outcome/prefix.
2. Perform one fresh primary-current batch and custody revalidation immediately
   before receipt persistence.
3. Create `terminal-reconciliation.<nonce>.receipt.json` without replacement,
   synchronize it and the target directory, and read it back through the held
   descriptor. An exact incumbent is replay; any changed or malformed incumbent
   conflicts.
4. Perform another fresh primary-current batch and custody/receipt revalidation
   immediately before retirement.
5. Move exact retained evidence through active -> retiring ->
   `retired.<nonce>.lease.json` with no-replace and directory synchronization at
   each boundary.

The terminal tool never sends D1 SQL writes and never retries an unavailable or
ambiguous provider read. Interpret its custody product literally. Only a fresh
revalidation of physical `active.lease.json` may return
`lease_retained=true`, `custody_status=retained_evidence_verified`, and
`lease_decision=retain`. Pre-inspection rejection returns null plus
`not_inspected`; inspection failure returns null plus `inspection_failed`;
retiring evidence returns null plus `retiring_evidence_verified`; and drift or
otherwise unverified custody returns null plus
`retained_evidence_unverified`. Those null states omit `lease_decision`; they
do not fabricate retention or retirement authority. Verified physical
retirement returns `lease_retained=false`,
`custody_status=retired_evidence_verified`, and `lease_decision=retired`, even
when the missing or invalid receipt then fails the request closed.

Failure before the receipt keeps the retained lease only when the response also
proves that active custody state.
Failure after the receipt leaves that durable receipt plus retained or retiring
evidence for exact replay. A terminal retirement with no exact receipt is an
order violation and cannot be repaired by creating a receipt afterward. Exact
replay after completed retirement validates the receipt and retired lease and
reproduces the receipt-bound expectation proof and versioned reconciliation
plan from the supplied manifest, including the complete outcome/prefix matrix,
before returning with zero provider calls.
If another exact caller completes retirement after initial inspection but
before reconciliation preparation, a preparation failure with exactly zero
provider calls permits one fresh custody inspection. It converges only through
the same exact completed-retirement replay validation. Once any provider call
has been attempted, the failure is not eligible for this convergence path and
remains reconciliation-required. Once a refresh or read reports unverified
custody, preserve that negative classification through terminal error handling;
a later physical inspection that appears restored cannot overwrite it.
Null, array, primitive, malformed,
duplicate-keyed, unknown-keyed, noncanonical, contradictory, hard-linked, or
conflicting namespace evidence fails closed. Never delete, rewrite, rename, or
copy these products manually.

For CI-built release bundles, a trusted `main` push through the `Rust
Validation` workflow uploads a native artifact for each supported Linux
architecture. Pull-request runs validate the same build and tool contract but
do not publish installable bundles:

The hosted binaries target GNU/Linux with glibc 2.39 or newer. Matching the CPU
architecture is not sufficient, and these bundles do not support musl hosts.

- `cloudflare-mcp-linux-x86_64-stdio-<git-sha>`
- `cloudflare-mcp-linux-aarch64-stdio-<git-sha>`

Each GitHub artifact contains the mode-preserving archive named after the
artifact with `.tar.gz` appended, plus that archive's `.sha256` file. The tar
archive contains:

- `cloudflare-mcp` (mode `0755`)
- `cloudflare-mcp.build-info`
- `release-provenance.json`
- `SHA256SUMS`

This is the preferred install source when the operator wants the local machine
to run exactly the binary GitHub Actions validated. Example retrieval:

```bash
set -euo pipefail
umask 077

arch="$(uname -m)"
case "$arch" in
  x86_64|aarch64) ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
sha="<exact-40-character-main-commit-sha>"
run_id="<trusted-main-push-run-id>"
destination="$(mktemp -d)"
trap 'find "$destination" -depth -delete' EXIT

scripts/download-trusted-release-bundle.sh \
  --run-id "$run_id" \
  --sha "$sha" \
  --arch "$arch" \
  --destination "$destination"

cd "$destination"
bundle="cloudflare-mcp-linux-${arch}-stdio-${sha}.tar.gz"
sha256sum -c "${bundle}.sha256"
mkdir extracted
tar -xzf "${bundle}" -C extracted
(cd extracted && sha256sum -c SHA256SUMS)
test "$(stat -c '%a' extracted/cloudflare-mcp)" = 755
grep -Fx "target-arch=${arch}" extracted/cloudflare-mcp.build-info
grep -Fx 'minimum-glibc=2.39' extracted/cloudflare-mcp.build-info
test "$(jq -r '.source.commit' extracted/release-provenance.json)" = "$sha"

glibc_identity="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
case "$glibc_identity" in
  'glibc '*) host_glibc="${glibc_identity#glibc }" ;;
  *) echo 'hosted cloudflare-mcp binaries require glibc 2.39 or newer' >&2; exit 1 ;;
esac
if ! printf '%s\n' 2.39 "$host_glibc" | sort -V -C; then
  echo "hosted cloudflare-mcp binaries require glibc 2.39 or newer; found ${host_glibc}" >&2
  exit 1
fi

version_dir="$HOME/.local/libexec/cloudflare-mcp/${sha}"
install -Dm0755 extracted/cloudflare-mcp "$version_dir/cloudflare-mcp"
install -m0644 extracted/cloudflare-mcp.build-info extracted/release-provenance.json \
  extracted/SHA256SUMS "$version_dir/"
```

After download, compare the installed file and the artifact manifest before
promoting a new `current` symlink or replacing the current binary in a versioned
install directory. Require the manifest source commit and the downloaded
artifact name to match the exact trusted `main` commit selected for install.
The download helper fails closed before requesting an artifact unless the
GitHub Actions API identifies the selected run as completed successfully from a
`push` to `main`, at that exact commit, in `sednalabs/cloudflare-mcp`, using
the `Rust Validation` workflow at `.github/workflows/rust-validation.yml`. Do
not replace this check with a PR run, a branch-name inference, or a manually
reconstructed commit identity.

## Staged Stable D1 Catalog Evidence

The internal catalog-evidence boundary is deliberately not an operator tool.
It is a pure prerequisite for a later guarded composition path and performs no
local/provider mutation. Its separate provider-custody adapter owns the only
Cloudflare reads that may construct catalog observation frames.

The adapter preallocates four distinct bounded dispatch/read identities before
I/O, then dispatches the fixed plan query twice for the canonical normalized
target. Each read makes one no-redirect HTTP attempt with no adapter retry. The
request/response custody binding covers the exact target, query and query
digest, plan digest, and 1,001-row/4 MiB caps. The raw provider body must reach
EOF within the byte cap before the shared duplicate-key-rejecting JSON decoder
accepts it under the 32-container nesting bound. Following Cloudflare's [D1
Query API response
contract](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/query/),
the envelope must include explicitly present, typed, empty `errors` and
`messages` arrays, while its one successful result set has only `meta`,
`results`, and `success`. ResponseInfo entries use the closed official `code`,
`message`, optional `documentation_url`, and optional `source.pointer` shape;
any non-empty array is terminal and its text is omitted from custody errors and
receipts. The result metadata must prove primary service plus
`changed_db=false`, `changes=0`, and `rows_written=0`. Only then does the adapter
normalize the fixed projection and construct a frame. Do not feed generic
`d1_query_read_only` JSON into this boundary.

Network ambiguity, redirects or non-success status, incomplete or oversized
bodies, duplicate keys, unknown envelope or ResponseInfo fields, excessive JSON
nesting, missing/malformed/non-empty envelope errors or messages, malformed
envelopes, non-primary or mutating metadata, response-binding drift, identity
reuse, a cap change, and the 1,001st row are
terminal unavailable evidence for that attempt. A first-read failure stops
before the second request; a second-read failure preserves the truthful
aggregate count and does not retry.

The success receipt binds each body completed at EOF by SHA-256 and byte size,
but retains neither body bytes nor private dispatch/read identities. Treat that
digest as comparison evidence only: without separately authorized exact bytes
it cannot replay the decode, and it never independently authenticates provider
origin or EOF outside the trusted HTTP adapter lifecycle. Errors remain
content-free and omit request/provider bodies and private identities.

This contract only establishes that two adapter-issued frames contain one
stable canonical typed version-5 catalog projection. The fixed query first
enumerates every physical `sqlite_schema` row with rowid, storage classes, and
exact hex bytes for type/name/owner. It does not filter malformed type rows or
erase TEXT/BLOB/integer distinctions with an unmarked cast. Only unique,
printable-ASCII TEXT table names whose catalog fields are structurally valid may
reach the `pragma_foreign_key_list()` table-valued function; all other schema
rows remain ordered explicit blockers.

Foreign-key facts contain child/parent, native typed id/sequence, `from`, `to`,
update/delete actions, and match mode with their exact storage classes and bytes.
Treat `to=NULL` and an empty TEXT target as different evidence. Composite
constraints require contiguous sequence cardinality and stable shared
parent/action/match facts. The projection retains SQL bytes only for valid table
relations and permits only bounded ASCII token classification. It records and
independently re-verifies case-insensitive `VIRTUAL` and `REPLACE` hits within
64 KiB. A virtual hit blocks because a module may mutate schema-table shadow
relations. A REPLACE hit blocks because a table or constraint conflict policy
can make plain INSERT or UPDATE delete an incumbent and run ON DELETE effects.
The scans may conservatively match identifiers or comments. Oversized sources
block before classification. View SQL and trigger bodies are excluded.
Unresolved parents or owners, malformed or aliased catalog rows, and
structurally unproven REPLACE/virtual/view/trigger write semantics remain
conservative blockers.
The row sentinel covers schema and foreign-key/blocker facts together.

The internal opaque verifier product may be handed only to later pure
consumers. Its aggregate-safe receipt counts fact families and blockers but
contains no relation names or SQL. It is not a full CREATE TABLE parser, trigger
parser, view interpreter, graph traversal, or authority decision. Physical read
independence/EOF, execution, custody, provider admission, DML composition,
mutation, deployment, and public routing must not infer authority from the
catalog receipt or projection alone.

The internal reserved-relation graph stage accepts only the opaque version-5
product, never caller JSON or a generic D1 response. Supply one non-empty set of
at most 64 configured reserved relation identities. They must be printable
ASCII, distinct under SQLite ASCII case folding, outside the automatic
`sqlite_`/`_cf_` families, and physically present as verified relations. The
stage adds every present automatic-family relation as a root. Missing roots and
all schema/foreign-key blocker facts are terminal unavailable evidence; do not
drop blocker rows and retry graph derivation.

The stage creates INSERT, UPDATE, and DELETE nodes only for verified table/view
relations. Valid index facts are linked and counted as non-addressable schema
auxiliaries. FK CASCADE, SET NULL, and SET DEFAULT create only their documented
operation-specific child-write edges; RESTRICT and NO ACTION create none.
Composite constraints contribute one edge group after the projection's exact
sequence/cardinality proof. The only SQL-byte classification is a conservative
case-insensitive search for `AUTOINCREMENT` within a 64-KiB table source. Any
match requires `sqlite_sequence` and adds table-insert to sequence-update; the
classifier intentionally prefers a false-positive denial over parsing DDL.
Any bounded `REPLACE` hit blocks the complete graph before a plain INSERT or
UPDATE decision can become `Allow`. Unavailable or oversized token sources also
block; do not infer a conflict policy from missing evidence.

For a future DML composer, use the graph module's closed internal expansion
contract and require every returned primitive decision to be `Allow`: REPLACE
and INSERT OR REPLACE are DELETE plus INSERT; UPSERT DO UPDATE is INSERT plus
UPDATE; UPDATE OR REPLACE is UPDATE plus DELETE. Unsupported compound forms
deny. This stage still performs no statement parsing, composition, admission,
execution, provider call, or mutation.

Do not parse trigger or view SQL to reopen a decision. All operations on a view
deny. All operations on, or FK paths reaching, a relation that owns any trigger
deny. Paths reaching a reserved root deny with higher precedence. Cycle-safe
traversal is limited to 1,000 relations, 3,000 nodes, and 4,096 edges. Any
unknown/malformed fact, missing relation/owner, unavailable table SQL token
source, unsupported action, or cap breach denies the complete product.

The success receipt is aggregate-safe: target/catalog/root/graph/decision
digests and counts only. It exposes no names, columns, SQL, account, or database
identity. This staged module has no public tool, provider call, DML composition,
admission, mutation, deployment, or live effect. Do not treat a graph receipt as
write authority; later composition must bind an exact classified DML operation
and relation to the opaque graph product.

The internal exact-plan composer is the next pure boundary. Supply only the
verified canonical target, exact version-2 DML plan plus its canonical digest,
the already classified exact lowercase relation and closed compound form, the
opaque version-5 catalog product, and the opaque version-3 graph product. Never
substitute caller JSON, a generic query response, or a serialized receipt for
either opaque product. The statement kind and form must agree. The composer
uses the graph module's exact primitive order and requires every primitive to
have a present `Allow` decision; missing, denied, duplicated, reordered,
unsupported, malformed, version-drifted, or cross-product-contradictory
evidence denies the complete composition.

The serializable receipt is aggregate-only and digest-binds the plan, target,
catalog, graph, classified relation/form, effective primitive set, and selected
decisions. It exposes none of those private names or bytes. This module does
not parse SQL, issue provider requests, admit or execute D1 writes, expose a
tool route, hold custody, or authorize dispatch. A later reviewed route may
consume the opaque product only after its exact classifier has bound the SQL
bytes to the supplied relation and compound form; a composition receipt by
itself is never execution authority.

The internal D1 DML attempt-custody stage is the next pure handoff. Supply only
the verified canonical target, opaque exact-plan composition product, and three
preallocated pairwise-distinct opaque identities for the operation,
execution-attempt, and provider request. Each identity must already satisfy the
closed 16-to-128-byte ASCII grammar. The stage hashes all three and binds them
to the target, exact execution plan, composition, and complete composition
receipt. Never substitute caller JSON, a serialized composition receipt, SQL,
or a generic provider response.

Persist the returned canonical private state only through the future reviewed
durable compare-and-exchange boundary. Its version-1 bytes are capped at 16 KiB and include one
trailing newline. On restore, require exact canonical bytes and reject missing,
oversized, malformed, duplicate-keyed, unknown-field, incomplete, predecessor,
digest-drifted, or internally contradictory evidence. An exact prepared replay
converges without changing state. A conflicting target, plan, composition, or
identity replay denies.

`prepared -> dispatch_reserved` is a non-authorizing atomic-CAS proposal. It
binds the exact prior-state and successor-state digests and explicitly requires
the later durable adapter to compare the exact current bytes and install that
successor atomically. Repeating the pure call with stale prepared bytes returns
the same proposal, never fresh dispatch authority. Only the adapter's one
successful compare-and-exchange may consume the reservation and permit the
provider call; a stale compare failure must stop before provider access. Once
the successor is durably installed, the same attempt is permanently
`do_not_redispatch_same_attempt`; a repeated reservation, transport uncertainty,
or missing/incomplete/malformed/contradictory response becomes
`reconciliation_required`. Do not infer that an unobserved response means the
provider did not accept the request.

The provider-terminal and readback inputs at this stage are typed caller
assertions, not authenticated evidence. Canonical digest syntax proves neither
artifact bytes nor provider/readback provenance. The later adapter must derive
the assertions from authenticated provider and independently executed readback
lifecycles before storing them in their separate slots. Either insertion order
must converge on the same canonical proposed terminal classification. Provider
success plus expected-state observation proposes `applied`; terminal provider
rejection plus absent-state readback proposes `not_applied`. One slot alone is
nonterminal, and a crossed pair stays under reconciliation. Receipts and errors
are aggregate/content-free and do not authorize persistence, provider/D1
access, artifact authentication, readback, retry, routing, admission,
deployment, or configuration.

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
