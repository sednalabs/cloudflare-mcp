# D1 row-write coordination core

This package is an inert, route-less coordination core for a future Cloudflare
Durable Object backed by SQLite. It deliberately has no `fetch` handler,
Wrangler configuration, binding, authentication ingress, provider capability,
queue, workflow, R2, Analytics Engine, D1, recipient data, or MCP wiring.

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
