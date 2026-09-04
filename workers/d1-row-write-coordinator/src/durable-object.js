import {
  D1RowWriteCoordinator,
  GENESIS_CONTRACT,
  PROTOCOL_VERSION,
  SCHEMA_VERSION,
} from "./index.js";

export const SERVICE_PATH = "/_internal/coordinate";
export const PROVISION_PATH = "/_internal/provision-genesis";

const HASH = /^[0-9a-f]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const SERVICE_OPERATIONS = new Set(["prepare", "reserve_dispatch", "observe_response"]);
const DENIED_OPERATIONS = new Set([
  "initialize_genesis",
  "delete",
  "rewind",
  "replace",
  "recover",
  "reset",
]);
const RECOVERY_OPERATIONS = new Set(["delete", "rewind", "replace", "recover", "reset"]);

function requireHash(value, name) {
  if (typeof value !== "string" || !HASH.test(value)) throw new Error(`${name}_must_be_opaque_sha256`);
  return value;
}

function requireRecoverySequence(value, name) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name}_must_be_positive_integer`);
  return value;
}

function decodeBase64(value, name) {
  if (typeof value !== "string" || !BASE64.test(value)) throw new Error(`${name}_must_be_base64`);
  try { return Uint8Array.from(atob(value), (character) => character.charCodeAt(0)); } catch { throw new Error(`${name}_must_be_base64`); }
}

function canonicalBinding(input, state) {
  return JSON.stringify({ authoritySha256: input.authoritySha256, bindingSha256: input.bindingSha256, classSha256: input.classSha256, entitlementSha256: input.entitlementSha256, generationSha256: input.generationSha256, genesisSha256: input.genesisSha256, objectKeySha256: input.objectKeySha256, recoveryEpochSha256: input.recoveryEpochSha256, recoverySequence: input.recoverySequence, schemaVersion: SCHEMA_VERSION, state, namespaceSha256: input.namespaceSha256, targetKeySha256: input.targetKeySha256 });
}

function entitlementMessage(input) {
  return [GENESIS_CONTRACT, PROTOCOL_VERSION, input.targetKeySha256, input.generationSha256, input.authoritySha256, input.genesisSha256, input.namespaceSha256, input.bindingSha256, input.objectKeySha256, input.classSha256, input.recoveryEpochSha256, input.recoverySequence, input.entitlementSha256].join("|");
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function errorStatus(error) {
  const message = error instanceof Error ? error.message : String(error ?? "unknown_error");
  if (/^(invalid_|.*_required|.*_must_|attempt_input_required)/.test(message)) return 400;
  if (/^(genesis_not_authorized|object_not_initialized|binding_mismatch|protocol_mismatch|namespace_mismatch|object_key_mismatch|class_mismatch|recovery_epoch_mismatch|recovery_sequence_mismatch|entitlement_mismatch|entitlement_invalid|entitlement_authority_|unsupported_operation|recovery_denied|adapter_witness_required)/.test(message)) return 409;
  if (/conflict|active_attempt|replay|transition/.test(message)) return 409;
  return 500;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export class D1RowWriteCoordinatorObject {
  #coordinator;
  #sql;
  #storage;
  #env;
  #objectId;

  constructor(state, env) {
    if (!state?.storage?.sql || typeof state.storage.sql.exec !== "function") throw new Error("sqlite_storage_required");
    if (typeof state.storage.transactionSync !== "function") throw new Error("transaction_sync_required");
    if (!env || typeof env.COORDINATOR_SERVICE_TOKEN !== "string" || env.COORDINATOR_SERVICE_TOKEN.length === 0) throw new Error("service_auth_not_configured");
    if (typeof env.GENESIS_PROVISIONER_TOKEN !== "string" || env.GENESIS_PROVISIONER_TOKEN.length === 0) throw new Error("genesis_auth_not_configured");
    this.#sql = state.storage.sql;
    this.#storage = state.storage;
    this.#env = env;
    requireHash(env.COORDINATOR_NAMESPACE_SHA256, "coordinator_namespace_sha256");
    requireHash(env.COORDINATOR_BINDING_SHA256, "coordinator_binding_sha256");
    requireHash(env.COORDINATOR_OBJECT_KEY_SHA256, "coordinator_object_key_sha256");
    requireHash(env.COORDINATOR_CLASS_SHA256, "coordinator_class_sha256");
    requireHash(env.COORDINATOR_RECOVERY_EPOCH_SHA256, "coordinator_recovery_epoch_sha256");
    requireHash(env.GENESIS_ENTITLEMENT_SHA256, "genesis_entitlement_sha256");
    const publicKey = decodeBase64(env.GENESIS_ENTITLEMENT_PUBLIC_KEY, "genesis_entitlement_public_key");
    if (publicKey.length !== 32) throw new Error("genesis_entitlement_public_key_length");
    requireRecoverySequence(Number(env.COORDINATOR_RECOVERY_SEQUENCE), "coordinator_recovery_sequence");
    if (typeof state.id?.toString !== "function") throw new Error("durable_object_id_required");
    if (typeof env.GENESIS_ENTITLEMENT_AUTHORITY?.fetch !== "function") throw new Error("genesis_authority_not_configured");
    this.#objectId = state.id.toString();
    if (String(env.COORDINATOR_SCHEMA_VERSION ?? SCHEMA_VERSION) !== String(SCHEMA_VERSION)) throw new Error("protocol_mismatch");
    this.#sql.exec("CREATE TABLE IF NOT EXISTS do_identity (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID");
    this.#coordinator = new D1RowWriteCoordinator({ sql: this.#sql });
  }

  #identityRows() {
    return this.#sql.exec("SELECT key, value FROM do_identity ORDER BY key").toArray();
  }

  async #actualObjectKeySha256() {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(this.#objectId));
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  async #assertRequestBinding(input) {
    requireHash(input.namespaceSha256, "namespace_sha256");
    requireHash(input.bindingSha256, "binding_sha256");
    requireHash(input.objectKeySha256, "object_key_sha256");
    requireHash(input.classSha256, "class_sha256");
    requireHash(input.recoveryEpochSha256, "recovery_epoch_sha256");
    requireRecoverySequence(input.recoverySequence, "recovery_sequence");
    if (input.namespaceSha256 !== this.#env.COORDINATOR_NAMESPACE_SHA256) throw new Error("namespace_mismatch");
    if (input.bindingSha256 !== this.#env.COORDINATOR_BINDING_SHA256) throw new Error("binding_mismatch");
    if (input.objectKeySha256 !== this.#env.COORDINATOR_OBJECT_KEY_SHA256) throw new Error("object_key_mismatch");
    if (input.classSha256 !== this.#env.COORDINATOR_CLASS_SHA256) throw new Error("class_mismatch");
    if (input.recoveryEpochSha256 !== this.#env.COORDINATOR_RECOVERY_EPOCH_SHA256) throw new Error("recovery_epoch_mismatch");
    if (input.recoverySequence !== Number(this.#env.COORDINATOR_RECOVERY_SEQUENCE)) throw new Error("recovery_sequence_mismatch");
    if (input.objectKeySha256 !== await this.#actualObjectKeySha256()) throw new Error("object_key_mismatch");
  }

  #assertStoredBinding(input, expectedState = "ready") {
    const rows = this.#identityRows();
    if (rows.length === 0) throw new Error("object_not_initialized");
    if (rows.length !== 1 || rows[0].key !== "binding") throw new Error("binding_mismatch");
    let values;
    try { values = JSON.parse(rows[0].value); } catch { throw new Error("binding_mismatch"); }
    if (rows[0].value !== canonicalBinding(input, values?.state) || values.state !== expectedState || values.entitlementSha256 !== this.#env.GENESIS_ENTITLEMENT_SHA256) throw new Error("object_not_initialized");
  }

  #storeBinding(input) {
    const value = canonicalBinding(input, "pending");
    this.#sql.exec("INSERT INTO do_identity(key, value) VALUES (?, ?)", "binding", value);
    const rows = this.#identityRows();
    if (rows.length !== 1 || rows[0].key !== "binding" || rows[0].value !== value) throw new Error("binding_readback_mismatch");
  }

  #markBindingReady(input) {
    const value = canonicalBinding(input, "ready");
    this.#sql.exec("UPDATE do_identity SET value = ? WHERE key = ?", value, "binding");
    const rows = this.#identityRows();
    if (rows.length !== 1 || rows[0].value !== value) throw new Error("binding_readback_mismatch");
  }

  #genesisExists(input) {
    const rows = this.#sql.exec("SELECT * FROM genesis WHERE target_key_sha256 = ? AND generation_sha256 = ?", input.targetKeySha256, input.generationSha256).toArray();
    return rows.length === 1 && rows[0].authority_sha256 === input.authoritySha256 && rows[0].genesis_sha256 === input.genesisSha256 && rows[0].protocol_version === PROTOCOL_VERSION && rows[0].schema_version === SCHEMA_VERSION;
  }

  async #verifyEntitlement(input) {
    const signature = decodeBase64(input.entitlementSignature, "entitlement_signature");
    if (signature.length !== 64) throw new Error("entitlement_signature_length");
    const publicKey = decodeBase64(this.#env.GENESIS_ENTITLEMENT_PUBLIC_KEY, "genesis_entitlement_public_key");
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    const valid = await crypto.subtle.verify({ name: "Ed25519" }, key, signature, new TextEncoder().encode(entitlementMessage(input)));
    if (!valid) throw new Error("entitlement_invalid");
    const authorityResponse = await this.#env.GENESIS_ENTITLEMENT_AUTHORITY.fetch(new Request("https://genesis-authority/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        contract: GENESIS_CONTRACT,
        targetKeySha256: input.targetKeySha256,
        generationSha256: input.generationSha256,
        authoritySha256: input.authoritySha256,
        genesisSha256: input.genesisSha256,
        objectKeySha256: input.objectKeySha256,
        recoveryEpochSha256: input.recoveryEpochSha256,
        recoverySequence: input.recoverySequence,
        entitlementSha256: input.entitlementSha256,
        entitlementSignature: input.entitlementSignature,
      }),
    }));
    if (!authorityResponse.ok) throw new Error("entitlement_authority_denied");
    let authorityResult;
    try { authorityResult = await authorityResponse.json(); } catch { throw new Error("entitlement_authority_invalid"); }
    if (!authorityResult || authorityResult.decision !== "new") throw new Error("entitlement_authority_replay");
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
      await this.#assertRequestBinding(input);
      this.#assertStoredBinding(input);
      if (DENIED_OPERATIONS.has(input.operation)) throw new Error("recovery_denied");
      if (!SERVICE_OPERATIONS.has(input.operation)) throw new Error("unsupported_operation");
      if (input.operation === "prepare") return jsonResponse(200, this.#coordinator.prepareAttempt(input));
      if (input.operation === "reserve_dispatch") return jsonResponse(200, this.#coordinator.reserveDispatch(input));
      return jsonResponse(200, this.#coordinator.observeResponse(input));
    } catch (error) {
      return jsonResponse(errorStatus(error), { error: error instanceof Error ? error.message : String(error ?? "unknown_error") });
    }
  }

  async #provision(request) {
    if (!this.#authorized(request, this.#env.GENESIS_PROVISIONER_TOKEN)) return jsonResponse(401, { error: "unauthorized" });
    try {
      const input = await this.#body(request);
      await this.#assertRequestBinding(input);
      requireHash(input.entitlementSha256, "entitlement_sha256");
      if (input.entitlementSha256 !== this.#env.GENESIS_ENTITLEMENT_SHA256) throw new Error("entitlement_mismatch");
      if (RECOVERY_OPERATIONS.has(input.operation)) throw new Error("recovery_denied");
      if (input.operation !== "initialize_genesis" || input.contract !== GENESIS_CONTRACT || input.protocolVersion !== PROTOCOL_VERSION) throw new Error("unsupported_operation");
      const rows = this.#identityRows();
      let existingState = null;
      if (rows.length !== 0) {
        if (rows.length !== 1 || rows[0].key !== "binding") throw new Error("binding_mismatch");
        try { existingState = JSON.parse(rows[0].value); } catch { throw new Error("binding_mismatch"); }
        if (existingState.state === "ready") {
          if (!this.#genesisExists(input)) throw new Error("recovery_denied");
          this.#assertStoredBinding(input);
          return jsonResponse(200, { protocolVersion: PROTOCOL_VERSION, decision: "exact_replay" });
        } else if (existingState.state !== "pending" || rows[0].value !== canonicalBinding(input, "pending")) {
          throw new Error("binding_mismatch");
        } else {
          if (!this.#genesisExists(input)) throw new Error("recovery_denied");
          this.#assertStoredBinding(input, "pending");
          this.#storage.transactionSync(() => this.#markBindingReady(input));
          return jsonResponse(200, { protocolVersion: PROTOCOL_VERSION, decision: "exact_replay" });
        }
      }
      await this.#verifyEntitlement(input);
      const result = this.#storage.transactionSync(() => {
        this.#storeBinding(input);
        const initialized = this.#coordinator.initializeGenesis(input);
        this.#markBindingReady(input);
        return initialized;
      });
      return jsonResponse(200, result);
    } catch (error) {
      return jsonResponse(errorStatus(error), { error: error instanceof Error ? error.message : String(error ?? "unknown_error") });
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
