export const PROTOCOL_VERSION = 1;
export const SCHEMA_VERSION = 1;
export const GENESIS_CONTRACT = "d1-row-write-do-genesis-v1";

const HASH = /^[0-9a-f]{64}$/;
const ACTIVE_PHASES = new Set([
  "prepared",
  "dispatch_reserved",
  "response_observed",
  "reconciliation_required",
]);
const TERMINAL_PHASES = new Set([
  "applied",
  "not_applied",
  "reconciliation_required",
  "reconciled",
]);

export function isActivePhase(phase) {
  return ACTIVE_PHASES.has(phase);
}

function requireHash(value, name) {
  if (typeof value !== "string" || !HASH.test(value)) {
    throw new Error(`${name}_must_be_opaque_sha256`);
  }
  return value;
}

function requireGenesisInput(input) {
  if (!input || input.contract !== GENESIS_CONTRACT || input.protocolVersion !== PROTOCOL_VERSION) {
    throw new Error("invalid_genesis_contract");
  }
  return {
    targetKeySha256: requireHash(input.targetKeySha256, "target_key_sha256"),
    generationSha256: requireHash(input.generationSha256, "generation_sha256"),
    authoritySha256: requireHash(input.authoritySha256, "authority_sha256"),
    genesisSha256: requireHash(input.genesisSha256, "genesis_sha256"),
  };
}

function requireAttemptInput(input) {
  if (!input) throw new Error("attempt_input_required");
  const values = {
    targetKeySha256: requireHash(input.targetKeySha256, "target_key_sha256"),
    generationSha256: requireHash(input.generationSha256, "generation_sha256"),
    operationIdSha256: requireHash(input.operationIdSha256, "operation_id_sha256"),
    executionAttemptIdSha256: requireHash(input.executionAttemptIdSha256, "execution_attempt_id_sha256"),
    providerRequestIdSha256: requireHash(input.providerRequestIdSha256, "provider_request_id_sha256"),
    planSha256: requireHash(input.planSha256, "plan_sha256"),
  };
  const identities = [
    values.operationIdSha256,
    values.executionAttemptIdSha256,
    values.providerRequestIdSha256,
  ];
  if (new Set(identities).size !== identities.length) throw new Error("attempt_identities_must_be_distinct");
  return values;
}

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS protocol_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID",
  "CREATE TABLE IF NOT EXISTS genesis (target_key_sha256 TEXT PRIMARY KEY, generation_sha256 TEXT NOT NULL, authority_sha256 TEXT NOT NULL, genesis_sha256 TEXT NOT NULL, protocol_version INTEGER NOT NULL, schema_version INTEGER NOT NULL) WITHOUT ROWID",
  "CREATE TABLE IF NOT EXISTS attempts (target_key_sha256 TEXT NOT NULL, generation_sha256 TEXT NOT NULL, operation_id_sha256 TEXT NOT NULL, execution_attempt_id_sha256 TEXT NOT NULL, provider_request_id_sha256 TEXT NOT NULL, plan_sha256 TEXT NOT NULL, phase TEXT NOT NULL, adapter_witness_present INTEGER NOT NULL CHECK(adapter_witness_present IN (0, 1)), PRIMARY KEY(target_key_sha256, generation_sha256, operation_id_sha256), UNIQUE(target_key_sha256, generation_sha256, execution_attempt_id_sha256), UNIQUE(target_key_sha256, generation_sha256, provider_request_id_sha256)) WITHOUT ROWID",
  "CREATE UNIQUE INDEX IF NOT EXISTS attempts_one_active ON attempts(target_key_sha256, generation_sha256) WHERE phase IN ('prepared', 'dispatch_reserved', 'response_observed', 'reconciliation_required')",
];

export class D1RowWriteCoordinator {
  #sql;

  constructor(storage) {
    if (!storage?.sql || typeof storage.sql.exec !== "function") throw new Error("sqlite_storage_required");
    this.#sql = storage.sql;
    for (const statement of SCHEMA) this.#sql.exec(statement);
    this.#sql.exec("INSERT OR IGNORE INTO protocol_meta(key, value) VALUES (?, ?)", "schema_version", String(SCHEMA_VERSION));
    const row = this.#rows("SELECT value FROM protocol_meta WHERE key = ?", "schema_version")[0];
    if (!row || row.value !== String(SCHEMA_VERSION)) throw new Error("schema_readback_mismatch");
  }

  #rows(query, ...bindings) {
    const values = bindings.length === 1 && Array.isArray(bindings[0]) ? bindings[0] : bindings;
    return this.#sql.exec(query, ...values).toArray();
  }

  #assertGenesis(input) {
    const g = {
      targetKeySha256: requireHash(input.targetKeySha256, "target_key_sha256"),
      generationSha256: requireHash(input.generationSha256, "generation_sha256"),
      authoritySha256: requireHash(input.authoritySha256, "authority_sha256"),
      genesisSha256: requireHash(input.genesisSha256, "genesis_sha256"),
    };
    const row = this.#rows("SELECT * FROM genesis WHERE target_key_sha256 = ?", [g.targetKeySha256])[0];
    if (!row || row.generation_sha256 !== g.generationSha256 || row.authority_sha256 !== g.authoritySha256 || row.genesis_sha256 !== g.genesisSha256 || row.protocol_version !== PROTOCOL_VERSION || row.schema_version !== SCHEMA_VERSION) {
      throw new Error("genesis_not_authorized");
    }
    return g;
  }

  initializeGenesis(input) {
    const g = requireGenesisInput(input);
    const existing = this.#rows("SELECT * FROM genesis WHERE target_key_sha256 = ?", [g.targetKeySha256])[0];
    if (existing) {
      if (existing.generation_sha256 !== g.generationSha256 || existing.authority_sha256 !== g.authoritySha256 || existing.genesis_sha256 !== g.genesisSha256 || existing.protocol_version !== PROTOCOL_VERSION || existing.schema_version !== SCHEMA_VERSION) throw new Error("genesis_conflict");
      return { protocolVersion: PROTOCOL_VERSION, decision: "exact_replay" };
    }
    this.#sql.exec("INSERT INTO genesis(target_key_sha256, generation_sha256, authority_sha256, genesis_sha256, protocol_version, schema_version) VALUES (?, ?, ?, ?, ?, ?)", g.targetKeySha256, g.generationSha256, g.authoritySha256, g.genesisSha256, PROTOCOL_VERSION, SCHEMA_VERSION);
    const read = this.#rows("SELECT * FROM genesis WHERE target_key_sha256 = ?", [g.targetKeySha256])[0];
    if (!read || read.generation_sha256 !== g.generationSha256 || read.authority_sha256 !== g.authoritySha256 || read.genesis_sha256 !== g.genesisSha256) throw new Error("sqlite_readback_mismatch");
    return { protocolVersion: PROTOCOL_VERSION, decision: "new" };
  }

  prepareAttempt(input) {
    const a = requireAttemptInput(input);
    this.#assertGenesis(input);
    const existing = this.#rows("SELECT * FROM attempts WHERE target_key_sha256 = ? AND generation_sha256 = ? AND operation_id_sha256 = ?", [a.targetKeySha256, a.generationSha256, a.operationIdSha256])[0];
    if (existing) {
      const exact = existing.execution_attempt_id_sha256 === a.executionAttemptIdSha256 && existing.provider_request_id_sha256 === a.providerRequestIdSha256 && existing.plan_sha256 === a.planSha256;
      if (!exact) throw new Error("conflicting_replay");
      return { protocolVersion: PROTOCOL_VERSION, decision: "exact_replay", phase: existing.phase, adapterWitnessPresent: existing.adapter_witness_present === 1 };
    }
    if (this.#rows("SELECT 1 FROM attempts WHERE target_key_sha256 = ? AND generation_sha256 = ? AND phase IN ('prepared', 'dispatch_reserved', 'response_observed', 'reconciliation_required')", [a.targetKeySha256, a.generationSha256]).length) throw new Error("conflicting_active_attempt");
    this.#sql.exec("INSERT INTO attempts(target_key_sha256, generation_sha256, operation_id_sha256, execution_attempt_id_sha256, provider_request_id_sha256, plan_sha256, phase, adapter_witness_present) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", a.targetKeySha256, a.generationSha256, a.operationIdSha256, a.executionAttemptIdSha256, a.providerRequestIdSha256, a.planSha256, "prepared", 0);
    const row = this.#rows("SELECT * FROM attempts WHERE target_key_sha256 = ? AND generation_sha256 = ? AND operation_id_sha256 = ?", [a.targetKeySha256, a.generationSha256, a.operationIdSha256])[0];
    if (!row || row.phase !== "prepared") throw new Error("sqlite_readback_mismatch");
    return { protocolVersion: PROTOCOL_VERSION, decision: "new", phase: "prepared", adapterWitnessPresent: false };
  }

  #transition(input, desiredPhase, witness) {
    const a = requireAttemptInput(input);
    this.#assertGenesis(input);
    if (!TERMINAL_PHASES.has(desiredPhase) && !["dispatch_reserved", "response_observed"].includes(desiredPhase)) throw new Error("invalid_phase");
    if ((desiredPhase === "applied" || desiredPhase === "reconciled") && witness !== true) throw new Error("adapter_witness_required");
    const row = this.#rows("SELECT * FROM attempts WHERE target_key_sha256 = ? AND generation_sha256 = ? AND operation_id_sha256 = ?", [a.targetKeySha256, a.generationSha256, a.operationIdSha256])[0];
    if (!row) throw new Error("attempt_not_found");
    if (row.execution_attempt_id_sha256 !== a.executionAttemptIdSha256 || row.provider_request_id_sha256 !== a.providerRequestIdSha256 || row.plan_sha256 !== a.planSha256) throw new Error("conflicting_replay");
    if (row.phase === desiredPhase && row.adapter_witness_present === (witness === true ? 1 : 0)) return { protocolVersion: PROTOCOL_VERSION, decision: "exact_replay", phase: row.phase, adapterWitnessPresent: row.adapter_witness_present === 1 };
    const valid = (row.phase === "prepared" && desiredPhase === "dispatch_reserved") || (row.phase === "dispatch_reserved" && desiredPhase === "response_observed") || (row.phase === "response_observed" && desiredPhase === "applied") || ((row.phase === "dispatch_reserved" || row.phase === "response_observed") && ["not_applied", "reconciliation_required"].includes(desiredPhase)) || (row.phase === "reconciliation_required" && desiredPhase === "reconciled");
    if (!valid) throw new Error("invalid_transition");
    this.#sql.exec("UPDATE attempts SET phase = ?, adapter_witness_present = ? WHERE target_key_sha256 = ? AND generation_sha256 = ? AND operation_id_sha256 = ?", desiredPhase, witness === true ? 1 : 0, a.targetKeySha256, a.generationSha256, a.operationIdSha256);
    const read = this.#rows("SELECT * FROM attempts WHERE target_key_sha256 = ? AND generation_sha256 = ? AND operation_id_sha256 = ?", [a.targetKeySha256, a.generationSha256, a.operationIdSha256])[0];
    if (!read || read.phase !== desiredPhase || read.adapter_witness_present !== (witness === true ? 1 : 0)) throw new Error("sqlite_readback_mismatch");
    return { protocolVersion: PROTOCOL_VERSION, decision: "transitioned", phase: desiredPhase, adapterWitnessPresent: witness === true };
  }

  reserveDispatch(input) { return this.#transition(input, "dispatch_reserved", false); }
  observeResponse(input) { return this.#transition(input, "response_observed", false); }
  closeAttempt(input) { return this.#transition(input, input.phase, input.adapterWitnessPresent === true); }
}
