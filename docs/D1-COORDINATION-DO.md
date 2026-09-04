# Durable Object coordination reset

The D1 mutation safety work needs a narrow architectural reset at the custody
boundary. Host-local descriptors cannot provide mutual exclusion across MCP
processes, workstations, restarts, or operators. The reset is deliberately not
a replacement of D1: D1 remains the relational operational store for audience,
preferences and exact ledgers; R2 remains durable private evidence custody;
Analytics Engine remains the measurement plane.

This repository contains an inert route-less coordination core and an
undeployed Durable Object wrapper in `workers/d1-row-write-coordinator`. The
wrapper has separate ordinary-service and privileged-genesis paths, but no
default Worker export or public route. It is intended to be the SQLite state
core of a later Durable Object, with these invariants:

* an externally authorised target generation is initialized exactly once;
* target and generation are represented only by opaque SHA-256 values;
* operation, execution-attempt, provider-request, plan, and authority identities
  are pairwise bound and opaque;
* at most one active attempt exists for a target and generation;
* exact replay converges without re-entering provider business logic, while a
  conflicting replay is denied;
* `prepared` → `dispatch_reserved` → `response_observed` precedes terminal
  `applied`, and `applied`/`reconciled` require an adapter witness;
* every write is immediately checked by stable SQLite readback.

The core does not make an external D1 operation atomic. A lost or ambiguous
provider response must remain reconciliation-required and must never trigger an
automatic retry. A future adapter must persist dispatch reservation before
external I/O and issue a non-constructible causal witness binding the exact
request, target, intended mutation, parsed provider response, and evidence.

Cloudflare's SQLite Durable Object API uses synchronous `ctx.storage.sql.exec()`
and supports transactional synchronous operations. The future deployment must
use the current official API and a reviewed `new_sqlite_classes` migration:

* [SQLite storage API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)
* [Durable Object access and routing](https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects/)

No Worker version, binding, route, credential, provider, or live resource is
created by this slice.

`initializeGenesis` is an inert protocol primitive, not an entitlement issuer.
The future activation cutline must separately provide authenticated execution
and provisioning authorities. It must prove ordinary execution is
open-existing only, and must deny deletion, rewind, replacement, and
unauthorised recovery. Until those gates are independently reviewed and
read-backed, this core remains development-only and cannot authorize a live
mutation.

The undeployed wrapper requires two separate authenticated paths. The ordinary
service path accepts only non-terminal coordination operations against an
already-bound object. A distinct provisioner credential and an externally
entitled opaque receipt are required before genesis can be established. Both
paths require exact opaque class, namespace, binding, object-key, recovery-epoch
and schema-version bindings. Missing or replaced state, stale epoch, PITR or
recovery ambiguity, deletion, rewind, replacement and unknown operations fail
closed. The package contains no default Worker export or public route; a future
deployment must add a reviewed internal service binding and `new_sqlite_classes`
migration separately.
