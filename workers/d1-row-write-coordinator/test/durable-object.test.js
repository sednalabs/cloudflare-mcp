import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { GENESIS_CONTRACT, PROTOCOL_VERSION } from "../src/index.js";
import { D1RowWriteCoordinatorObject, PROVISION_PATH, SERVICE_PATH } from "../src/durable-object.js";

class SqliteStorage {
  constructor(database = new DatabaseSync(":memory:")) { this.database = database; }
  exec(query, ...bindings) {
    const statements = query.split(";").map((s) => s.trim()).filter(Boolean);
    let result;
    for (const statement of statements) {
      if (/^\s*select\b/i.test(statement)) result = { toArray: () => this.database.prepare(statement).all(...bindings) };
      else { this.database.prepare(statement).run(...bindings); result = { toArray: () => [] }; }
    }
    return result ?? { toArray: () => [] };
  }
}

const h = (character) => character.repeat(64);
const env = {
  COORDINATOR_SERVICE_TOKEN: "service-test-token",
  GENESIS_PROVISIONER_TOKEN: "provisioner-test-token",
  COORDINATOR_NAMESPACE_SHA256: h("e"),
  COORDINATOR_BINDING_SHA256: h("b"),
  COORDINATOR_OBJECT_KEY_SHA256: h("f"),
  COORDINATOR_CLASS_SHA256: h("1"),
  COORDINATOR_RECOVERY_EPOCH_SHA256: h("2"),
  GENESIS_ENTITLEMENT_SHA256: h("3"),
  COORDINATOR_SCHEMA_VERSION: "1",
};
const genesis = {
  operation: "initialize_genesis", contract: GENESIS_CONTRACT, protocolVersion: PROTOCOL_VERSION,
  targetKeySha256: h("a"), generationSha256: h("9"), authoritySha256: h("c"), genesisSha256: h("d"),
  namespaceSha256: h("e"), bindingSha256: h("b"), objectKeySha256: h("f"), classSha256: h("1"), recoveryEpochSha256: h("2"), entitlementSha256: h("3"),
};
const attempt = {
  ...genesis, operation: "prepare", planSha256: h("8"), operationIdSha256: h("1"),
  executionAttemptIdSha256: h("2"), providerRequestIdSha256: h("3"),
};

async function call(object, pathname, body, token) {
  const response = await object.fetch(new Request(`https://internal${pathname}`, {
    method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(body),
  }));
  return { status: response.status, body: await response.json() };
}

test("requires privileged genesis and preserves service-only lifecycle across re-instantiation", async () => {
  const storage = new SqliteStorage();
  const state = { storage: { sql: storage } };
  const object = new D1RowWriteCoordinatorObject(state, env);
  assert.equal((await call(object, SERVICE_PATH, attempt, env.COORDINATOR_SERVICE_TOKEN)).status, 409);
  assert.equal((await call(object, PROVISION_PATH, genesis, env.GENESIS_PROVISIONER_TOKEN)).body.decision, "new");
  assert.equal((await call(object, SERVICE_PATH, attempt, env.COORDINATOR_SERVICE_TOKEN)).body.phase, "prepared");
  const restarted = new D1RowWriteCoordinatorObject(state, env);
  assert.equal((await call(restarted, SERVICE_PATH, attempt, env.COORDINATOR_SERVICE_TOKEN)).body.decision, "exact_replay");
});

test("denies public paths, recovery operations, and binding/version mismatches", async () => {
  const storage = new SqliteStorage();
  const state = { storage: { sql: storage } };
  const object = new D1RowWriteCoordinatorObject(state, env);
  assert.equal((await call(object, "/public", attempt, env.COORDINATOR_SERVICE_TOKEN)).status, 404);
  assert.equal((await call(object, SERVICE_PATH, { ...attempt, operation: "delete" }, env.COORDINATOR_SERVICE_TOKEN)).status, 409);
  assert.equal((await call(object, PROVISION_PATH, { ...genesis, namespaceSha256: h("0") }, env.GENESIS_PROVISIONER_TOKEN)).status, 409);
  assert.equal((await call(object, PROVISION_PATH, genesis, env.COORDINATOR_SERVICE_TOKEN)).status, 401);
  assert.equal((await call(object, SERVICE_PATH, { ...attempt, namespaceSha256: h("0") }, env.COORDINATOR_SERVICE_TOKEN)).status, 409);
  assert.equal((await call(object, SERVICE_PATH, { ...attempt, classSha256: h("0") }, env.COORDINATOR_SERVICE_TOKEN)).status, 409);
  assert.equal((await call(object, SERVICE_PATH, { ...attempt, recoveryEpochSha256: h("0") }, env.COORDINATOR_SERVICE_TOKEN)).status, 409);
});

test("serializes two service instances and denies rewind or replacement", async () => {
  const storage = new SqliteStorage();
  const state = { storage: { sql: storage } };
  const first = new D1RowWriteCoordinatorObject(state, env);
  const second = new D1RowWriteCoordinatorObject(state, env);
  assert.equal((await call(first, PROVISION_PATH, genesis, env.GENESIS_PROVISIONER_TOKEN)).body.decision, "new");
  assert.equal((await call(first, SERVICE_PATH, attempt, env.COORDINATOR_SERVICE_TOKEN)).status, 200);
  assert.equal((await call(second, SERVICE_PATH, { ...attempt, operationIdSha256: h("4") }, env.COORDINATOR_SERVICE_TOKEN)).status, 409);
  for (const operation of ["rewind", "replace", "recover", "reset"]) {
    assert.equal((await call(second, SERVICE_PATH, { ...attempt, operation }, env.COORDINATOR_SERVICE_TOKEN)).body.error, "recovery_denied");
  }
});

test("rejects a version-overlap object before accepting service requests", async () => {
  assert.throws(() => new D1RowWriteCoordinatorObject({ storage: { sql: new SqliteStorage() } }, { ...env, COORDINATOR_SCHEMA_VERSION: "2" }), /protocol_mismatch/);
});

test("empty or replacement object fails closed for ordinary execution", async () => {
  const storage = new SqliteStorage();
  const object = new D1RowWriteCoordinatorObject({ storage: { sql: storage } }, env);
  const response = await call(object, SERVICE_PATH, attempt, env.COORDINATOR_SERVICE_TOKEN);
  assert.equal(response.status, 409);
  assert.equal(response.body.error, "object_not_initialized");
});
