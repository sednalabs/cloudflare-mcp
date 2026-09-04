# D1 row-write coordination core

This package is an undeployed, route-less coordination core for a future
Cloudflare Durable Object backed by SQLite. It is a generic surviving-D1 and
migration capability, not a decision that newsletter audience state must move
to a Durable Object; any AudienceDO replacement is a separate architecture
decision. It deliberately has no default
Worker export, Wrangler configuration, public route, recipient data, queue,
workflow, or production resource. Its authenticated internal service boundary
includes a complete opt-in provider lifecycle; bindings are required at
invocation time and are never supplied by this repository.

`src/durable-object.js` provides the next, still undeployed, Durable Object
class. Its two internal-only paths require separate bearer credentials: the
ordinary service path can open an existing binding and advance non-terminal
coordination states, while the privileged provisioning path alone may establish
genesis. There is no default Worker export or public route.

The class requires deployment-time configuration for opaque namespace, binding,
class, object-key, recovery-epoch, and genesis-entitlement SHA-256 values, a
recovery sequence, an Ed25519 entitlement-verification key, an external
entitlement-authority service binding, and separate service and provisioner
credentials. These values are intentionally not supplied here. Every request
must carry the matching opaque binding tuple and the actual Durable Object id
must hash to the configured object key; an empty/replacement object, stale
recovery epoch, version mismatch, unknown operation, deletion, rewind,
replacement, reset, or recovery request fails closed. Ordinary service
requests never call `initializeGenesis`.

The core records only opaque SHA-256 identities and a versioned genesis. It
serializes one active attempt per target and generation, distinguishes exact
replay from conflicting replay, and requires an adapter witness before an
`applied` or `reconciled` terminal state. An observed response is not itself a
causal provider witness; an uncertain outcome remains reconciliation-required.
Every write is followed by an exact SQLite readback.

`operation: "execute_d1"` is the narrow internal lifecycle adapter. It binds a
versioned plan and separate consent digest to three pairwise-distinct attempt
identities, persists `dispatch_reserved` inside `transactionSync()` before the
single D1 binding call, and never retries that call. The plan permits no more
than 100 bound parameters (the documented D1 limit), and its parameters use a
closed type-tagged encoding that rejects unsupported, non-finite, undefined,
and sparse values. A complete strict D1
response is reduced to an aggregate-safe result, stored in a private R2
evidence bucket under an opaque key, and then terminalised by a compare-and-
read-back boundary. Provider response loss, malformed/incomplete evidence,
R2 failure, changed durable state, or CAS/read-back uncertainty produces
`reconciliation_required`; an exact replay returns that state without another
provider or R2 call. Response and evidence digests are derived inside the
adapter, not accepted as caller assertions. The returned `providerCalls` and
`providerEffect` fields distinguish zero, one, and unknown rather than
implying that a missing response was a successful no-op.

The adapter accepts only documented D1 result metadata names (including
optional duration, row counters, colo/region, size and timings fields) and
validates their types; unknown metadata is evidence ambiguity. Only the
required `served_by_primary`, `changed_db`, `changes` and `rows_written` fields
are canonicalized into the causal witness. A primary response with
`changed_db: false` and zero counters is terminal `not_applied`; a changed
response is terminal `applied` only when both returned mutation counters stay
within the plan's exact `maxRows` bound; an over-bound response is
`reconciliation_required`.

The SQL boundary intentionally accepts one semicolon-free DML statement only;
it does not parse comments or literals to broaden that contract. Multi-statement
or ambiguous SQL is rejected before the provider call and must use a separately
reviewed batch protocol.

The lifecycle requires deployment-time `D1_DATABASE` and
`D1_EVIDENCE_BUCKET` bindings on the internal object. It is not wired to the
MCP tool surface or a live Cloudflare resource in this slice: the generic
`d1_execute_write` MCP tool remains retired until a separately reviewed
MCP-to-internal-DO adapter, credentials, deployment, and live readback are
commissioned. No provider, audience, recipient, or production-send effect is
authorized by these source changes.

Run the focused tests with `npm test`. Node's built-in `node:sqlite` is used
only by the synthetic test fixture; no dependency or broad build system is
introduced.

Any later deployment must use a separately reviewed Wrangler migration with a
`new_sqlite_classes` declaration and an authenticated control ingress. Object
names must be derived from opaque target-generation material, never raw target,
recipient, SQL, or provider identifiers.

`initializeGenesis` is only an inert core primitive. The provisioning path
additionally requires a valid Ed25519 entitlement signature and a
`decision: "new"` response from the separately privileged entitlement-authority
service. External verification happens before the synchronous storage
transaction; binding insertion, genesis initialization, and ready promotion
then share one `transactionSync` boundary and roll back together on failure.
A pending state with matching genesis is a narrowly bounded recovery case and
can promote to ready without replaying the consumed entitlement; a pending
state without matching genesis, or a ready object with missing/replaced genesis,
fails closed. Activation remains blocked until a separately governed
authenticated execution/provisioning split proves ordinary open-existing
execution, deletion/rewind/replacement denial, and recovery authority.
