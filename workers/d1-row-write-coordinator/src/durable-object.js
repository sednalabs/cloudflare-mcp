import {
  D1RowWriteCoordinator,
  GENESIS_CONTRACT,
  PROTOCOL_VERSION,
  SCHEMA_VERSION,
} from "./index.js";

export const SERVICE_PATH = "/_internal/coordinate";
export const PROVISION_PATH = "/_internal/provision-genesis";

const HASH = /^[0-9a-f]{64}$/;
const SERVICE_OPERATIONS = new Set(["prepare", "reserve_dispatch", "observe_response"]);
const DENIED_OPERATIONS = new Set([
  "initialize_genesis",
  "delete",
  "rewind",
  "replace",
  "recover",
  "reset",
]);

function requireHash(value, name) {
  if (typeof value !== "string" || !HASH.test(value)) throw new Error(`${name}_must_be_opaque_sha256`);
  return value;
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function errorStatus(error) {
  if (/^(invalid_|.*_required|.*_must_|attempt_input_required)/.test(error.message)) return 400;
  if (/^(genesis_not_authorized|object_not_initialized|binding_mismatch|protocol_mismatch|namespace_mismatch|object_key_mismatch|class_mismatch|recovery_epoch_mismatch|entitlement_mismatch|unsupported_operation|recovery_denied|adapter_witness_required)/.test(error.message)) return 409;
  if (/conflict|active_attempt|replay|transition/.test(error.message)) return 409;
  return 500;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export class D1RowWriteCoordinatorObject {
  #coordinator;
  #sql;
  #env;

  constructor(state, env) {
    if (!state?.storage?.sql || typeof state.storage.sql.exec !== "function") throw new Error("sqlite_storage_required");
    if (!env || typeof env.COORDINATOR_SERVICE_TOKEN !== "string" || env.COORDINATOR_SERVICE_TOKEN.length === 0) throw new Error("service_auth_not_configured");
    if (typeof env.GENESIS_PROVISIONER_TOKEN !== "string" || env.GENESIS_PROVISIONER_TOKEN.length === 0) throw new Error("genesis_auth_not_configured");
    this.#sql = state.storage.sql;
    this.#env = env;
    requireHash(env.COORDINATOR_NAMESPACE_SHA256, "coordinator_namespace_sha256");
    requireHash(env.COORDINATOR_BINDING_SHA256, "coordinator_binding_sha256");
    requireHash(env.COORDINATOR_OBJECT_KEY_SHA256, "coordinator_object_key_sha256");
    requireHash(env.COORDINATOR_CLASS_SHA256, "coordinator_class_sha256");
    requireHash(env.COORDINATOR_RECOVERY_EPOCH_SHA256, "coordinator_recovery_epoch_sha256");
    requireHash(env.GENESIS_ENTITLEMENT_SHA256, "genesis_entitlement_sha256");
    if (String(env.COORDINATOR_SCHEMA_VERSION ?? SCHEMA_VERSION) !== String(SCHEMA_VERSION)) throw new Error("protocol_mismatch");
    this.#sql.exec("CREATE TABLE IF NOT EXISTS do_identity (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID");
    this.#coordinator = new D1RowWriteCoordinator({ sql: this.#sql });
  }

  #identityRows() {
    return this.#sql.exec("SELECT key, value FROM do_identity ORDER BY key").toArray();
  }

  #assertRequestBinding(input) {
    requireHash(input.namespaceSha256, "namespace_sha256");
    requireHash(input.bindingSha256, "binding_sha256");
    requireHash(input.objectKeySha256, "object_key_sha256");
    requireHash(input.classSha256, "class_sha256");
    requireHash(input.recoveryEpochSha256, "recovery_epoch_sha256");
    if (input.namespaceSha256 !== this.#env.COORDINATOR_NAMESPACE_SHA256) throw new Error("namespace_mismatch");
    if (input.bindingSha256 !== this.#env.COORDINATOR_BINDING_SHA256) throw new Error("binding_mismatch");
    if (input.objectKeySha256 !== this.#env.COORDINATOR_OBJECT_KEY_SHA256) throw new Error("object_key_mismatch");
    if (input.classSha256 !== this.#env.COORDINATOR_CLASS_SHA256) throw new Error("class_mismatch");
    if (input.recoveryEpochSha256 !== this.#env.COORDINATOR_RECOVERY_EPOCH_SHA256) throw new Error("recovery_epoch_mismatch");
  }

  #assertStoredBinding(input) {
    const rows = this.#identityRows();
    if (rows.length === 0) throw new Error("object_not_initialized");
    const values = Object.fromEntries(rows.map((row) => [row.key, row.value]));
    if (rows.length !== 7 || values.schema_version !== String(SCHEMA_VERSION) || values.class_sha256 !== input.classSha256 || values.namespace_sha256 !== input.namespaceSha256 || values.binding_sha256 !== input.bindingSha256 || values.object_key_sha256 !== input.objectKeySha256 || values.recovery_epoch_sha256 !== input.recoveryEpochSha256 || values.entitlement_sha256 !== this.#env.GENESIS_ENTITLEMENT_SHA256) throw new Error("binding_mismatch");
  }

  #storeBinding(input) {
    this.#sql.exec("INSERT INTO do_identity(key, value) VALUES (?, ?)", "schema_version", String(SCHEMA_VERSION));
    this.#sql.exec("INSERT INTO do_identity(key, value) VALUES (?, ?)", "class_sha256", input.classSha256);
    this.#sql.exec("INSERT INTO do_identity(key, value) VALUES (?, ?)", "namespace_sha256", input.namespaceSha256);
    this.#sql.exec("INSERT INTO do_identity(key, value) VALUES (?, ?)", "binding_sha256", input.bindingSha256);
    this.#sql.exec("INSERT INTO do_identity(key, value) VALUES (?, ?)", "object_key_sha256", input.objectKeySha256);
    this.#sql.exec("INSERT INTO do_identity(key, value) VALUES (?, ?)", "recovery_epoch_sha256", input.recoveryEpochSha256);
    this.#sql.exec("INSERT INTO do_identity(key, value) VALUES (?, ?)", "entitlement_sha256", input.entitlementSha256);
    const rows = this.#identityRows();
    if (rows.length !== 7 || rows.filter((row) => row.key !== "schema_version").some((row) => !HASH.test(row.value))) throw new Error("binding_readback_mismatch");
  }

  async #body(request) {
    if (request.method !== "POST") throw new Error("method_not_allowed");
    const contentType = request.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().startsWith("application/json")) throw new Error("json_body_required");
    let value;
    try { value = await request.json(); } catch { throw new Error("invalid_json"); }
    if (!isObject(value)) throw new Error("json_object_required");
    return value;
  }

  #authorized(request, token) {
    return request.headers.get("authorization") === `Bearer ${token}`;
  }

  async #service(request) {
    if (!this.#authorized(request, this.#env.COORDINATOR_SERVICE_TOKEN)) return jsonResponse(401, { error: "unauthorized" });
    try {
      const input = await this.#body(request);
      this.#assertRequestBinding(input);
      this.#assertStoredBinding(input);
      if (DENIED_OPERATIONS.has(input.operation)) throw new Error("recovery_denied");
      if (!SERVICE_OPERATIONS.has(input.operation)) throw new Error("unsupported_operation");
      if (input.operation === "prepare") return jsonResponse(200, this.#coordinator.prepareAttempt(input));
      if (input.operation === "reserve_dispatch") return jsonResponse(200, this.#coordinator.reserveDispatch(input));
      return jsonResponse(200, this.#coordinator.observeResponse(input));
    } catch (error) {
      return jsonResponse(errorStatus(error), { error: error.message });
    }
  }

  async #provision(request) {
    if (!this.#authorized(request, this.#env.GENESIS_PROVISIONER_TOKEN)) return jsonResponse(401, { error: "unauthorized" });
    try {
      const input = await this.#body(request);
      this.#assertRequestBinding(input);
      requireHash(input.entitlementSha256, "entitlement_sha256");
      if (input.entitlementSha256 !== this.#env.GENESIS_ENTITLEMENT_SHA256) throw new Error("entitlement_mismatch");
      const rows = this.#identityRows();
      if (rows.length !== 0) {
        this.#assertStoredBinding(input);
      }
      if (input.operation !== "initialize_genesis" || input.contract !== GENESIS_CONTRACT || input.protocolVersion !== PROTOCOL_VERSION) throw new Error("unsupported_operation");
      const result = this.#coordinator.initializeGenesis(input);
      if (rows.length === 0) this.#storeBinding(input);
      return jsonResponse(200, result);
    } catch (error) {
      return jsonResponse(errorStatus(error), { error: error.message });
    }
  }

  // This class is exported for an internal service binding only. There is no
  // default Worker fetch handler or public route in this package.
  async fetch(request) {
    const pathname = new URL(request.url).pathname;
    if (pathname === SERVICE_PATH) return this.#service(request);
    if (pathname === PROVISION_PATH) return this.#provision(request);
    return jsonResponse(404, { error: "not_found" });
  }
}
