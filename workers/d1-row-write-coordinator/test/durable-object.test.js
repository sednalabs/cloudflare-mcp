import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { GENESIS_CONTRACT, PROTOCOL_VERSION } from "../src/index.js";
import { D1RowWriteCoordinatorObject, PROVISION_PATH, SERVICE_PATH } from "../src/durable-object.js";
import { canonicalParameterEncoding } from "../src/provider-lifecycle.js";

class SqliteStorage {
  constructor(database = new DatabaseSync(":memory:"), { failOnReadyUpdate = false, failOnAppliedUpdate = false } = {}) { this.database = database; this.failOnReadyUpdate = failOnReadyUpdate; this.failOnAppliedUpdate = failOnAppliedUpdate; }
  transactionSync(callback) {
    this.database.exec("BEGIN");
    try {
      const result = callback();
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }
  exec(query, ...bindings) {
    const statements = query.split(";").map((s) => s.trim()).filter(Boolean);
    let result;
    for (const statement of statements) {
      if (this.failOnReadyUpdate && /^UPDATE do_identity SET value/i.test(statement)) throw new Error("forced_ready_failure");
      if (this.failOnAppliedUpdate && /^UPDATE provider_lifecycle_attempts SET phase = \?/i.test(statement)) throw new Error("forced_applied_failure");
      if (/^\s*select\b/i.test(statement)) result = { toArray: () => this.database.prepare(statement).all(...bindings) };
      else { this.database.prepare(statement).run(...bindings); result = { toArray: () => [] }; }
    }
    return result ?? { toArray: () => [] };
  }
}

const h = (character) => character.repeat(64);
const objectId = "opaque-do-object-a";
const objectKey = createHash("sha256").update(objectId).digest("hex");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const publicKeyBytes = publicKey.export({ type: "spki", format: "der" }).subarray(-32);

class EntitlementAuthority {
  #seen = new Set();
  async fetch(request) {
    const body = await request.json();
    const receiptKey = `${body.entitlementSignature}:${body.objectKeySha256}:${body.recoverySequence}`;
    if (this.#seen.has(receiptKey)) return new Response(JSON.stringify({ decision: "replay" }), { status: 200 });
    this.#seen.add(receiptKey);
    return new Response(JSON.stringify({ decision: "new" }), { status: 200 });
  }
}

const env = {
  COORDINATOR_SERVICE_TOKEN: "service-test-token",
  GENESIS_PROVISIONER_TOKEN: "provisioner-test-token",
  COORDINATOR_NAMESPACE_SHA256: h("e"),
  COORDINATOR_BINDING_SHA256: h("b"),
  COORDINATOR_OBJECT_KEY_SHA256: objectKey,
  COORDINATOR_CLASS_SHA256: h("1"),
  COORDINATOR_RECOVERY_EPOCH_SHA256: h("2"),
  GENESIS_ENTITLEMENT_SHA256: h("3"),
  GENESIS_ENTITLEMENT_PUBLIC_KEY: publicKeyBytes.toString("base64"),
  COORDINATOR_RECOVERY_SEQUENCE: "1",
  COORDINATOR_SCHEMA_VERSION: "1",
  GENESIS_ENTITLEMENT_AUTHORITY: new EntitlementAuthority(),
};
const testEnv = () => ({ ...env, GENESIS_ENTITLEMENT_AUTHORITY: new EntitlementAuthority() });
const stateFor = (storage, id = objectId) => ({ id: { toString: () => id }, storage: { sql: storage, transactionSync: (callback) => storage.transactionSync(callback) } });
const genesis = {
  operation: "initialize_genesis", contract: GENESIS_CONTRACT, protocolVersion: PROTOCOL_VERSION,
  targetKeySha256: h("a"), generationSha256: h("9"), authoritySha256: h("c"), genesisSha256: h("d"),
  namespaceSha256: h("e"), bindingSha256: h("b"), objectKeySha256: objectKey, classSha256: h("1"), recoveryEpochSha256: h("2"), recoverySequence: 1, entitlementSha256: h("3"),
};
genesis.entitlementSignature = sign(null, Buffer.from([
  GENESIS_CONTRACT, PROTOCOL_VERSION, genesis.targetKeySha256, genesis.generationSha256,
  genesis.authoritySha256, genesis.genesisSha256, genesis.namespaceSha256,
  genesis.bindingSha256, genesis.objectKeySha256, genesis.classSha256,
  genesis.recoveryEpochSha256, genesis.recoverySequence, genesis.entitlementSha256,
].join("|")), privateKey).toString("base64");
const attempt = {
  ...genesis, operation: "prepare", planSha256: h("8"), operationIdSha256: h("1"),
  executionAttemptIdSha256: h("2"), providerRequestIdSha256: h("3"),
};

async function sha256(value) {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function lifecycleAttempt(overrides = {}) {
  const sql = "UPDATE newsletter_state SET enabled = ?";
  const params = [true];
  const plan = {
    version: 1, operation: "d1_execute_write", targetKeySha256: h("a"), generationSha256: h("9"),
    statementKind: "UPDATE", sqlSha256: await sha256(sql), paramsSha256: await sha256(canonicalParameterEncoding(params)), maxRows: 100,
  };
  return {
    ...genesis, operation: "execute_d1", planSha256: await sha256(JSON.stringify(plan)), consentSha256: h("f"),
    operationIdSha256: h("5"), executionAttemptIdSha256: h("6"), providerRequestIdSha256: h("7"), plan, sql, params,
    ...overrides,
  };
}

test("uses a closed, collision-resistant D1 parameter encoding", () => {
  assert.notEqual(canonicalParameterEncoding([null]), canonicalParameterEncoding(["null"]));
  assert.notEqual(canonicalParameterEncoding([0]), canonicalParameterEncoding([-0]));
  assert.notEqual(canonicalParameterEncoding([true]), canonicalParameterEncoding([1]));
  assert.throws(() => canonicalParameterEncoding(new Array(101).fill(1)), /bounded_array/);
  assert.throws(() => canonicalParameterEncoding([undefined]), /type_invalid/);
  assert.throws(() => canonicalParameterEncoding([Number.NaN]), /number_invalid/);
  assert.throws(() => canonicalParameterEncoding([Number.POSITIVE_INFINITY]), /number_invalid/);
  assert.throws(() => canonicalParameterEncoding([[1]]), /type_invalid/);
  const sparse = [];
  sparse.length = 1;
  assert.throws(() => canonicalParameterEncoding(sparse), /hole_invalid/);
});

async function call(object, pathname, body, token) {
  const response = await object.fetch(new Request(`https://internal${pathname}`, {
    method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(body),
  }));
  return { status: response.status, body: await response.json() };
}

test("requires privileged genesis and preserves service-only lifecycle across re-instantiation", async () => {
  const storage = new SqliteStorage();
  const state = stateFor(storage);
  const environment = testEnv();
  const object = new D1RowWriteCoordinatorObject(state, environment);
  assert.equal((await call(object, SERVICE_PATH, attempt, environment.COORDINATOR_SERVICE_TOKEN)).status, 409);
  assert.equal((await call(object, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN)).body.decision, "new");
  assert.equal((await call(object, SERVICE_PATH, attempt, environment.COORDINATOR_SERVICE_TOKEN)).body.phase, "prepared");
  const restarted = new D1RowWriteCoordinatorObject(state, environment);
  assert.equal((await call(restarted, SERVICE_PATH, attempt, environment.COORDINATOR_SERVICE_TOKEN)).body.decision, "exact_replay");
  assert.equal((await call(restarted, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN)).body.decision, "exact_replay");
  assert.equal((await call(restarted, PROVISION_PATH, { ...genesis, operation: "delete" }, environment.GENESIS_PROVISIONER_TOKEN)).body.error, "recovery_denied");
});

test("denies public paths, recovery operations, and binding/version mismatches", async () => {
  const storage = new SqliteStorage();
  const state = stateFor(storage);
  const environment = testEnv();
  const object = new D1RowWriteCoordinatorObject(state, environment);
  assert.equal((await call(object, "/public", attempt, environment.COORDINATOR_SERVICE_TOKEN)).status, 404);
  assert.equal((await call(object, SERVICE_PATH, { ...attempt, operation: "delete" }, environment.COORDINATOR_SERVICE_TOKEN)).status, 409);
  assert.equal((await call(object, PROVISION_PATH, { ...genesis, namespaceSha256: h("0") }, environment.GENESIS_PROVISIONER_TOKEN)).status, 409);
  assert.equal((await call(object, PROVISION_PATH, { ...genesis, entitlementSignature: Buffer.alloc(64).toString("base64") }, environment.GENESIS_PROVISIONER_TOKEN)).body.error, "entitlement_invalid");
  assert.equal((await call(object, PROVISION_PATH, genesis, environment.COORDINATOR_SERVICE_TOKEN)).status, 401);
  assert.equal((await call(object, SERVICE_PATH, { ...attempt, namespaceSha256: h("0") }, environment.COORDINATOR_SERVICE_TOKEN)).status, 409);
  assert.equal((await call(object, SERVICE_PATH, { ...attempt, classSha256: h("0") }, environment.COORDINATOR_SERVICE_TOKEN)).status, 409);
  assert.equal((await call(object, SERVICE_PATH, { ...attempt, recoveryEpochSha256: h("0") }, environment.COORDINATOR_SERVICE_TOKEN)).status, 409);
  assert.equal((await call(object, SERVICE_PATH, { ...attempt, recoverySequence: 2 }, environment.COORDINATOR_SERVICE_TOKEN)).status, 409);
});

test("serializes two service instances and denies rewind or replacement", async () => {
  const storage = new SqliteStorage();
  const state = stateFor(storage);
  const environment = testEnv();
  const first = new D1RowWriteCoordinatorObject(state, environment);
  const second = new D1RowWriteCoordinatorObject(state, environment);
  assert.equal((await call(first, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN)).body.decision, "new");
  assert.equal((await call(first, SERVICE_PATH, attempt, environment.COORDINATOR_SERVICE_TOKEN)).status, 200);
  assert.equal((await call(second, SERVICE_PATH, { ...attempt, operationIdSha256: h("4") }, environment.COORDINATOR_SERVICE_TOKEN)).status, 409);
  for (const operation of ["rewind", "replace", "recover", "reset"]) {
    assert.equal((await call(second, SERVICE_PATH, { ...attempt, operation }, environment.COORDINATOR_SERVICE_TOKEN)).body.error, "recovery_denied");
  }
  storage.database.prepare("DELETE FROM genesis").run();
  assert.equal((await call(second, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN)).body.error, "recovery_denied");
});

test("rejects a version-overlap object before accepting service requests", async () => {
  assert.throws(() => new D1RowWriteCoordinatorObject(stateFor(new SqliteStorage()), { ...testEnv(), COORDINATOR_SCHEMA_VERSION: "2" }), /protocol_mismatch/);
});

test("empty or replacement object fails closed for ordinary execution", async () => {
  const storage = new SqliteStorage();
  const environment = testEnv();
  const object = new D1RowWriteCoordinatorObject(stateFor(storage), environment);
  const response = await call(object, SERVICE_PATH, attempt, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(response.status, 409);
  assert.equal(response.body.error, "object_not_initialized");
});

test("binds service execution to the actual durable-object identity", async () => {
  const object = new D1RowWriteCoordinatorObject(stateFor(new SqliteStorage(), "opaque-do-object-b"), testEnv());
  const response = await call(object, SERVICE_PATH, attempt, env.COORDINATOR_SERVICE_TOKEN);
  assert.equal(response.status, 409);
  assert.equal(response.body.error, "object_key_mismatch");
});

test("promotes a matching pending genesis without replaying external entitlement", async () => {
  const storage = new SqliteStorage();
  const environment = testEnv();
  const object = new D1RowWriteCoordinatorObject(stateFor(storage), environment);
  assert.equal((await call(object, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN)).body.decision, "new");
  storage.database.prepare("UPDATE do_identity SET value = replace(value, '\"ready\"', '\"pending\"') WHERE key = 'binding'").run();
  const restarted = new D1RowWriteCoordinatorObject(stateFor(storage), environment);
  assert.equal((await call(restarted, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN)).body.decision, "exact_replay");
  assert.equal((await call(restarted, SERVICE_PATH, attempt, environment.COORDINATOR_SERVICE_TOKEN)).body.phase, "prepared");
});

test("rolls back binding and genesis together on a mid-provision failure", async () => {
  const storage = new SqliteStorage(undefined, { failOnReadyUpdate: true });
  const environment = testEnv();
  const object = new D1RowWriteCoordinatorObject(stateFor(storage), environment);
  const failed = await call(object, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN);
  assert.equal(failed.status, 500);
  assert.equal(failed.body.error, "forced_ready_failure");
  assert.equal(storage.database.prepare("SELECT COUNT(*) AS count FROM do_identity").get().count, 0);
  assert.equal(storage.database.prepare("SELECT COUNT(*) AS count FROM genesis").get().count, 0);
  const retry = await call(object, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN);
  assert.equal(retry.status, 409);
  assert.equal(retry.body.error, "entitlement_authority_replay");
  assert.equal(storage.database.prepare("SELECT COUNT(*) AS count FROM do_identity").get().count, 0);
  assert.equal(storage.database.prepare("SELECT COUNT(*) AS count FROM genesis").get().count, 0);
});

test("renders non-Error failures safely on both ingress paths", async () => {
  const storage = new SqliteStorage();
  const environment = testEnv();
  const object = new D1RowWriteCoordinatorObject(stateFor(storage), environment);
  storage.exec = () => { throw "service-string"; };
  const serviceFailure = await call(object, SERVICE_PATH, attempt, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(serviceFailure.status, 500);
  assert.equal(serviceFailure.body.error, "service-string");

  class ThrowingAuthority { async fetch() { throw "authority-string"; } }
  const provisionObject = new D1RowWriteCoordinatorObject(stateFor(new SqliteStorage()), { ...env, GENESIS_ENTITLEMENT_AUTHORITY: new ThrowingAuthority() });
  const provisionFailure = await call(provisionObject, PROVISION_PATH, genesis, env.GENESIS_PROVISIONER_TOKEN);
  assert.equal(provisionFailure.status, 500);
  assert.equal(provisionFailure.body.error, "authority-string");
});

test("executes one strict D1 request after durable reservation and keeps private R2 evidence", async () => {
  const storage = new SqliteStorage();
  const d1 = {
    calls: 0,
    prepare(sql) {
      this.calls += 1;
      assert.equal(sql, "UPDATE newsletter_state SET enabled = ?");
      return { bind: () => ({ run: async () => ({ success: true, results: [], meta: { served_by_primary: true, changed_db: true, changes: 1, rows_written: 1, duration: 1.25, last_row_id: 2, rows_read: 1, served_by_colo: "SFO", served_by_region: "WNAM", size_after: 123, timings: { sql_duration_ms: 1.1 } } }) }) };
    },
  };
  const evidence = { writes: [], async put(key, body, options) { this.writes.push({ key, body: new Uint8Array(body), options }); } };
  const environment = { ...testEnv(), D1_DATABASE: d1, D1_EVIDENCE_BUCKET: evidence };
  const object = new D1RowWriteCoordinatorObject(stateFor(storage), environment);
  assert.equal((await call(object, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN)).body.decision, "new");
  const input = await lifecycleAttempt();
  const first = await call(object, SERVICE_PATH, input, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(first.body.status, "applied");
  assert.equal(first.body.providerCalls, 1);
  assert.equal(first.body.providerEffect, "one");
  assert.equal(first.body.evidenceCustody, "private_r2");
  assert.equal(d1.calls, 1);
  assert.equal(evidence.writes.length, 1);
  const replay = await call(object, SERVICE_PATH, input, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(replay.body.status, "applied");
  assert.equal(replay.body.exactReplay, true);
  assert.equal(d1.calls, 1);
});

test("classifies a strict primary no-op as not_applied and rejects unknown metadata", async () => {
  const storage = new SqliteStorage();
  let response = { success: true, results: [], meta: { served_by_primary: true, changed_db: false, changes: 0, rows_written: 0 } };
  const d1 = { calls: 0, prepare() { this.calls += 1; return { bind: () => ({ run: async () => response }) }; } };
  const evidence = { writes: [], async put(key, body, options) { this.writes.push({ key, body, options }); } };
  const environment = { ...testEnv(), D1_DATABASE: d1, D1_EVIDENCE_BUCKET: evidence };
  const object = new D1RowWriteCoordinatorObject(stateFor(storage), environment);
  await call(object, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN);
  const input = await lifecycleAttempt();
  const noOp = await call(object, SERVICE_PATH, input, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(noOp.body.status, "not_applied");
  assert.equal(noOp.body.providerEffect, "zero");
  assert.equal(noOp.body.providerCalls, 1);
  assert.equal((await call(object, SERVICE_PATH, input, environment.COORDINATOR_SERVICE_TOKEN)).body.exactReplay, true);
  assert.equal(d1.calls, 1);

  const unknownStorage = new SqliteStorage();
  const unknownD1 = { calls: 0, prepare() { this.calls += 1; return { bind: () => ({ run: async () => ({ success: true, results: [], meta: { served_by_primary: true, changed_db: true, changes: 1, rows_written: 1, untrusted: true } }) }) }; } };
  const unknownEvidence = { async put() { throw new Error("not_reached"); } };
  const unknownObject = new D1RowWriteCoordinatorObject(stateFor(unknownStorage), { ...testEnv(), D1_DATABASE: unknownD1, D1_EVIDENCE_BUCKET: unknownEvidence });
  await call(unknownObject, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN);
  const unknown = await call(unknownObject, SERVICE_PATH, await lifecycleAttempt(), environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(unknown.body.status, "reconciliation_required");
  assert.equal(unknownD1.calls, 1);
});

test("does not terminalize a provider response beyond the approved row bound", async () => {
  const storage = new SqliteStorage();
  const d1 = { calls: 0, prepare() { this.calls += 1; return { bind: () => ({ run: async () => ({ success: true, results: [], meta: { served_by_primary: true, changed_db: true, changes: 2, rows_written: 2 } }) }) }; } };
  const evidence = { writes: [], async put() { this.writes.push(true); } };
  const environment = { ...testEnv(), D1_DATABASE: d1, D1_EVIDENCE_BUCKET: evidence };
  const object = new D1RowWriteCoordinatorObject(stateFor(storage), environment);
  await call(object, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN);
  const base = await lifecycleAttempt();
  const plan = { ...base.plan, maxRows: 1 };
  const input = { ...base, plan, planSha256: await sha256(JSON.stringify(plan)) };
  const result = await call(object, SERVICE_PATH, input, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(result.body.status, "reconciliation_required");
  assert.equal(result.body.providerEffect, "unknown");
  assert.equal(result.body.providerCalls, 1);
  assert.equal(evidence.writes.length, 0);
  assert.equal(d1.calls, 1);
});

test("turns provider response loss into reconciliation_required and never redispatches", async () => {
  const storage = new SqliteStorage();
  const d1 = { calls: 0, prepare() { this.calls += 1; return { bind: () => ({ run: async () => { throw new Error("transport_lost"); } }) }; } };
  const evidence = { async put() { throw new Error("not reached"); } };
  const environment = { ...testEnv(), D1_DATABASE: d1, D1_EVIDENCE_BUCKET: evidence };
  const object = new D1RowWriteCoordinatorObject(stateFor(storage), environment);
  assert.equal((await call(object, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN)).body.decision, "new");
  const input = await lifecycleAttempt();
  const first = await call(object, SERVICE_PATH, input, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(first.body.status, "reconciliation_required");
  assert.equal(first.body.providerCalls, 1);
  assert.equal(first.body.retryDecision, "reconciliation_only");
  const replay = await call(object, SERVICE_PATH, input, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(replay.body.status, "reconciliation_required");
  assert.equal(replay.body.exactReplay, true);
  assert.equal(d1.calls, 1);
});

test("turns R2 custody failure into reconciliation_required without leaving a reservation", async () => {
  const storage = new SqliteStorage();
  const d1 = { calls: 0, prepare() { this.calls += 1; return { bind: () => ({ run: async () => ({ success: true, results: [], meta: { served_by_primary: true, changed_db: true, changes: 1, rows_written: 1 } }) }) }; } };
  const evidence = { async put() { throw new Error("r2_unavailable"); } };
  const environment = { ...testEnv(), D1_DATABASE: d1, D1_EVIDENCE_BUCKET: evidence };
  const object = new D1RowWriteCoordinatorObject(stateFor(storage), environment);
  await call(object, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN);
  const input = await lifecycleAttempt();
  const response = await call(object, SERVICE_PATH, input, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(response.status, 200);
  assert.equal(response.body.status, "reconciliation_required");
  assert.equal(response.body.providerCalls, 1);
  assert.equal(response.body.evidenceCustody, "not_available");
  assert.equal(d1.calls, 1);
  const replay = await call(object, SERVICE_PATH, input, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(replay.body.exactReplay, true);
  assert.equal(d1.calls, 1);
});

test("preserves response and custody digests when terminal CAS fails after R2", async () => {
  const storage = new SqliteStorage(undefined, { failOnAppliedUpdate: true });
  const d1 = { calls: 0, prepare() { this.calls += 1; return { bind: () => ({ run: async () => ({ success: true, results: [], meta: { served_by_primary: true, changed_db: true, changes: 1, rows_written: 1 } }) }) }; } };
  const evidence = { writes: [], async put(key, body, options) { this.writes.push({ key, body, options }); } };
  const environment = { ...testEnv(), D1_DATABASE: d1, D1_EVIDENCE_BUCKET: evidence };
  const object = new D1RowWriteCoordinatorObject(stateFor(storage), environment);
  await call(object, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN);
  const input = await lifecycleAttempt();
  const result = await call(object, SERVICE_PATH, input, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(result.body.status, "reconciliation_required");
  assert.equal(result.body.providerCalls, 1);
  assert.match(result.body.responseSha256, /^[0-9a-f]{64}$/);
  assert.match(result.body.evidenceKeySha256, /^[0-9a-f]{64}$/);
  assert.match(result.body.witnessSha256, /^[0-9a-f]{64}$/);
  assert.equal(result.body.evidenceCustody, "private_r2");
  assert.equal(d1.calls, 1);
  assert.equal(evidence.writes.length, 1);
  const replay = await call(object, SERVICE_PATH, input, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(replay.body.exactReplay, true);
  assert.equal(d1.calls, 1);
  assert.equal(evidence.writes.length, 1);
});

test("denies a conflicting replay before any D1 request", async () => {
  const storage = new SqliteStorage();
  const d1 = { calls: 0, prepare() { this.calls += 1; return { bind: () => ({ run: async () => ({ success: true, results: [], meta: { served_by_primary: true, changed_db: false, changes: 0, rows_written: 0 } }) }) }; } };
  const evidence = { async put() {} };
  const environment = { ...testEnv(), D1_DATABASE: d1, D1_EVIDENCE_BUCKET: evidence };
  const object = new D1RowWriteCoordinatorObject(stateFor(storage), environment);
  await call(object, PROVISION_PATH, genesis, environment.GENESIS_PROVISIONER_TOKEN);
  const input = await lifecycleAttempt();
  assert.equal((await call(object, SERVICE_PATH, input, environment.COORDINATOR_SERVICE_TOKEN)).body.status, "not_applied");
  const conflict = await call(object, SERVICE_PATH, { ...input, consentSha256: h("0") }, environment.COORDINATOR_SERVICE_TOKEN);
  assert.equal(conflict.status, 409);
  assert.equal(conflict.body.error, "conflicting_replay");
  assert.equal(d1.calls, 1);
});
