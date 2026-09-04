import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { GENESIS_CONTRACT, PROTOCOL_VERSION } from "../src/index.js";
import { D1RowWriteCoordinatorObject, PROVISION_PATH, SERVICE_PATH } from "../src/durable-object.js";

class SqliteStorage {
  constructor(database = new DatabaseSync(":memory:"), { failOnReadyUpdate = false } = {}) { this.database = database; this.failOnReadyUpdate = failOnReadyUpdate; }
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
