# D1 row-write coordination core

This package is an inert, route-less coordination core for a future Cloudflare
Durable Object backed by SQLite. It deliberately has no `fetch` handler,
Wrangler configuration, binding, authentication ingress, provider capability,
queue, workflow, R2, Analytics Engine, D1, recipient data, or MCP wiring.

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

`initializeGenesis` is only an inert core primitive. It does not issue or prove
external entitlement. Activation remains blocked until a separately governed
authenticated execution/provisioning split proves ordinary open-existing
execution, deletion/rewind/replacement denial, and recovery authority.
