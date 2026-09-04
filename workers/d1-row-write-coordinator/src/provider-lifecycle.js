// The provider lifecycle is deliberately kept separate from the small
// coordination core.  The core owns the serialised reservation; this module
// owns the one D1 call, private response custody, and terminal classification.
// It is only reachable through the authenticated, undeployed internal DO
// service.  There is no public Worker export here.

const HASH = /^[0-9a-f]{64}$/;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
// Cloudflare D1's documented query API accepts at most 100 bound parameters.
const MAX_PARAMS = 100;
const PHASES = new Set(["dispatch_reserved", "applied", "not_applied", "reconciliation_required"]);
const STATEMENT_KINDS = new Set(["INSERT", "UPDATE", "DELETE", "REPLACE"]);
// D1's result metadata is extensible, but the adapter must not turn arbitrary
// provider fields into causal evidence. Keep the documented API surface closed
// and retain only the four fields that this lifecycle uses for classification.
const D1_META_KEYS = new Set([
  "changed_db", "changes", "duration", "last_row_id", "rows_read",
  "rows_written", "served_by_colo", "served_by_primary", "served_by_region",
  "size_after", "timings",
]);

function hashBytes(bytes) {
  return crypto.subtle.digest("SHA-256", bytes).then((digest) =>
    Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")
  );
}

function requireHash(value, name) {
  if (typeof value !== "string" || !HASH.test(value)) throw new Error(`${name}_must_be_opaque_sha256`);
  return value;
}

function requireString(value, name) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name}_required`);
  return value;
}

function requireInteger(value, name, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`${name}_must_be_bounded_integer`);
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(value);
}

function canonicalParameter(value, index) {
  if (value === null) return ["null"];
  if (typeof value === "string") return ["string", value];
  if (typeof value === "boolean") return ["boolean", value];
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`params_${index}_number_invalid`);
    // Preserve the only otherwise-colliding JavaScript number spelling.
    return ["number", Object.is(value, -0) ? "-0" : String(value)];
  }
  throw new Error(`params_${index}_type_invalid`);
}

export function canonicalParameterEncoding(params) {
  if (!Array.isArray(params) || params.length > MAX_PARAMS) throw new Error("params_must_be_bounded_array");
  const values = [];
  for (let index = 0; index < params.length; index += 1) {
    if (!Object.hasOwn(params, index)) throw new Error(`params_${index}_hole_invalid`);
    values.push(canonicalParameter(params[index], index));
  }
  return canonicalJson({ version: 1, values });
}

function canonicalPlan(input) {
  const plan = input.plan;
  if (!plan || typeof plan !== "object" || Array.isArray(plan)) throw new Error("plan_required");
  if (Object.keys(plan).sort().join(",") !== "generationSha256,maxRows,operation,paramsSha256,sqlSha256,statementKind,targetKeySha256,version") throw new Error("plan_shape_invalid");
  const result = {
    version: plan.version,
    operation: plan.operation,
    targetKeySha256: plan.targetKeySha256,
    generationSha256: plan.generationSha256,
    statementKind: plan.statementKind,
    sqlSha256: plan.sqlSha256,
    paramsSha256: plan.paramsSha256,
    maxRows: plan.maxRows,
  };
  if (plan.version !== 1 || plan.operation !== "d1_execute_write") throw new Error("plan_contract_invalid");
  requireHash(result.targetKeySha256, "plan_target_key_sha256");
  requireHash(result.generationSha256, "plan_generation_sha256");
  if (!STATEMENT_KINDS.has(result.statementKind)) throw new Error("plan_statement_kind_invalid");
  requireHash(result.sqlSha256, "plan_sql_sha256");
  requireHash(result.paramsSha256, "plan_params_sha256");
  requireInteger(result.maxRows, "plan_max_rows", 1, 1000);
  return result;
}

function strictResult(value, maxRows) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("d1_response_not_object");
  const keys = Object.keys(value).sort().join(",");
  if (keys !== "meta,results,success") throw new Error("d1_response_shape_invalid");
  if (value.success !== true || !Array.isArray(value.results)) throw new Error("d1_response_not_successful");
  if (!value.meta || typeof value.meta !== "object" || Array.isArray(value.meta)) throw new Error("d1_response_meta_invalid");
  for (const key of Object.keys(value.meta)) if (!D1_META_KEYS.has(key)) throw new Error("d1_response_metadata_invalid");
  if (value.meta.served_by_primary !== true || typeof value.meta.changed_db !== "boolean") throw new Error("d1_response_primary_or_change_invalid");
  for (const key of ["changes", "rows_written"]) {
    if (!Number.isSafeInteger(value.meta[key]) || value.meta[key] < 0) throw new Error(`d1_response_${key}_invalid`);
  }
  if (value.meta.changes > maxRows || value.meta.rows_written > maxRows) throw new Error("d1_response_exceeds_plan_max_rows");
  for (const key of ["duration", "last_row_id", "rows_read", "size_after"]) {
    if (key in value.meta && (!Number.isFinite(value.meta[key]) || value.meta[key] < 0)) throw new Error(`d1_response_${key}_invalid`);
  }
  for (const key of ["served_by_colo", "served_by_region"]) {
    if (key in value.meta && (typeof value.meta[key] !== "string" || value.meta[key].length > 128)) throw new Error(`d1_response_${key}_invalid`);
  }
  if ("timings" in value.meta) {
    const timings = value.meta.timings;
    if (!timings || typeof timings !== "object" || Array.isArray(timings) || Object.keys(timings).some((key) => key !== "sql_duration_ms") || ("sql_duration_ms" in timings && (!Number.isFinite(timings.sql_duration_ms) || timings.sql_duration_ms < 0))) throw new Error("d1_response_timings_invalid");
  }
  if (!value.meta.changed_db && (value.meta.changes !== 0 || value.meta.rows_written !== 0)) throw new Error("d1_response_metadata_contradictory");
  return value;
}

function canonicalResponse(value) {
  return canonicalJson({
    success: value.success,
    results: value.results,
    meta: {
      served_by_primary: value.meta.served_by_primary,
      changed_db: value.meta.changed_db,
      changes: value.meta.changes,
      rows_written: value.meta.rows_written,
    },
  });
}

function resultSummary(row, exactReplay = false) {
  const effect = row.provider_effect;
  return {
    protocolVersion: 1,
    operation: "d1_execute_write",
    status: row.phase,
    exactReplay,
    providerCalls: row.provider_calls === null ? "unknown" : row.provider_calls,
    providerEffect: effect,
    evidenceCustody: row.evidence_key_sha256 ? "private_r2" : "not_available",
    responseSha256: row.response_sha256,
    responseSizeBytes: row.response_size_bytes,
    evidenceKeySha256: row.evidence_key_sha256,
    witnessSha256: row.witness_sha256,
    retryDecision: row.phase === "applied" || row.phase === "not_applied" ? "terminal_replay_only" : "reconciliation_only",
  };
}

export class D1ProviderLifecycle {
  #sql;
  #transactionSync;
  #coordinator;
  #env;

  constructor({ sql, transactionSync, coordinator, env }) {
    if (!sql || typeof sql.exec !== "function") throw new Error("sqlite_storage_required");
    if (typeof transactionSync !== "function") throw new Error("transaction_sync_required");
    if (!coordinator) throw new Error("coordinator_required");
    this.#sql = sql;
    this.#transactionSync = transactionSync;
    this.#coordinator = coordinator;
    this.#env = env ?? {};
    for (const statement of [
      "CREATE TABLE IF NOT EXISTS provider_lifecycle_attempts (target_key_sha256 TEXT NOT NULL, generation_sha256 TEXT NOT NULL, operation_id_sha256 TEXT NOT NULL, execution_attempt_id_sha256 TEXT NOT NULL, provider_request_id_sha256 TEXT NOT NULL, plan_sha256 TEXT NOT NULL, consent_sha256 TEXT NOT NULL, binding_sha256 TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('dispatch_reserved', 'applied', 'not_applied', 'reconciliation_required')), provider_calls INTEGER CHECK(provider_calls IS NULL OR provider_calls IN (0, 1)), provider_effect TEXT NOT NULL CHECK(provider_effect IN ('zero', 'one', 'unknown')), response_sha256 TEXT, response_size_bytes INTEGER, evidence_key_sha256 TEXT, witness_sha256 TEXT, PRIMARY KEY(target_key_sha256, generation_sha256, operation_id_sha256), UNIQUE(target_key_sha256, generation_sha256, execution_attempt_id_sha256), UNIQUE(target_key_sha256, generation_sha256, provider_request_id_sha256)) WITHOUT ROWID",
      "CREATE UNIQUE INDEX IF NOT EXISTS provider_lifecycle_one_active ON provider_lifecycle_attempts(target_key_sha256, generation_sha256) WHERE phase = 'dispatch_reserved'",
    ]) this.#sql.exec(statement);
  }

  #rows(query, ...bindings) {
    return this.#sql.exec(query, ...bindings).toArray();
  }

  async #validatedInput(input) {
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("execute_input_required");
    const targetKeySha256 = requireHash(input.targetKeySha256, "target_key_sha256");
    const generationSha256 = requireHash(input.generationSha256, "generation_sha256");
    const authoritySha256 = requireHash(input.authoritySha256, "authority_sha256");
    const genesisSha256 = requireHash(input.genesisSha256, "genesis_sha256");
    const operationIdSha256 = requireHash(input.operationIdSha256, "operation_id_sha256");
    const executionAttemptIdSha256 = requireHash(input.executionAttemptIdSha256, "execution_attempt_id_sha256");
    const providerRequestIdSha256 = requireHash(input.providerRequestIdSha256, "provider_request_id_sha256");
    const planSha256 = requireHash(input.planSha256, "plan_sha256");
    const consentSha256 = requireHash(input.consentSha256, "consent_sha256");
    if (new Set([operationIdSha256, executionAttemptIdSha256, providerRequestIdSha256]).size !== 3) throw new Error("attempt_identities_must_be_distinct");
    const plan = canonicalPlan(input);
    if (plan.targetKeySha256 !== targetKeySha256 || plan.generationSha256 !== generationSha256) throw new Error("plan_binding_mismatch");
    const sql = requireString(input.sql, "sql");
    if (sql.includes(";")) throw new Error("sql_must_be_one_statement");
    if (sql.trim().split(/\s+/, 1)[0].toUpperCase() !== plan.statementKind) throw new Error("plan_statement_kind_mismatch");
    const params = input.params ?? [];
    const paramsEncoding = canonicalParameterEncoding(params);
    const maxRows = requireInteger(plan.maxRows, "max_rows", 1, 1000);
    const sqlSha256 = await hashBytes(new TextEncoder().encode(sql));
    const paramsSha256 = await hashBytes(new TextEncoder().encode(paramsEncoding));
    if (sqlSha256 !== plan.sqlSha256 || paramsSha256 !== plan.paramsSha256) throw new Error("plan_payload_digest_mismatch");
    const derivedPlanSha256 = await hashBytes(new TextEncoder().encode(canonicalJson(plan)));
    if (derivedPlanSha256 !== planSha256) throw new Error("plan_digest_mismatch");
    const bindingSha256 = await hashBytes(new TextEncoder().encode([targetKeySha256, generationSha256, operationIdSha256, executionAttemptIdSha256, providerRequestIdSha256, planSha256, consentSha256].join("|")));
    return { targetKeySha256, generationSha256, authoritySha256, genesisSha256, operationIdSha256, executionAttemptIdSha256, providerRequestIdSha256, planSha256, consentSha256, bindingSha256, plan, sql, params, maxRows };
  }

  #existing(input) {
    return this.#rows("SELECT * FROM provider_lifecycle_attempts WHERE target_key_sha256 = ? AND generation_sha256 = ? AND operation_id_sha256 = ?", input.targetKeySha256, input.generationSha256, input.operationIdSha256)[0] ?? null;
  }

  #assertReplay(row, input) {
    for (const [column, value] of [["execution_attempt_id_sha256", input.executionAttemptIdSha256], ["provider_request_id_sha256", input.providerRequestIdSha256], ["plan_sha256", input.planSha256], ["consent_sha256", input.consentSha256], ["binding_sha256", input.bindingSha256]]) {
      if (row[column] !== value) throw new Error("conflicting_replay");
    }
  }

  #markReconciliation(input, providerCalls, response = null) {
    this.#transactionSync(() => {
      const row = this.#existing(input);
      if (!row) throw new Error("lifecycle_state_missing");
      if (row.phase === "applied" || row.phase === "not_applied") return;
      this.#coordinator.closeAttempt({ ...input, phase: "reconciliation_required" });
      this.#sql.exec("UPDATE provider_lifecycle_attempts SET phase = 'reconciliation_required', provider_calls = ?, provider_effect = 'unknown', response_sha256 = COALESCE(?, response_sha256), response_size_bytes = COALESCE(?, response_size_bytes), evidence_key_sha256 = COALESCE(?, evidence_key_sha256), witness_sha256 = COALESCE(?, witness_sha256) WHERE target_key_sha256 = ? AND generation_sha256 = ? AND operation_id_sha256 = ? AND phase = 'dispatch_reserved'", providerCalls, response?.sha256 ?? null, response?.size ?? null, response?.evidenceKeySha256 ?? null, response?.witnessSha256 ?? null, input.targetKeySha256, input.generationSha256, input.operationIdSha256);
      const read = this.#existing(input);
      if (!read || read.phase !== "reconciliation_required") throw new Error("terminal_cas_readback_mismatch");
    });
  }

  async execute(input) {
    const value = await this.#validatedInput(input);
    const existing = this.#existing(value);
    if (existing) {
      this.#assertReplay(existing, value);
      if (PHASES.has(existing.phase) && existing.phase !== "dispatch_reserved") return resultSummary(existing, true);
      this.#markReconciliation(value, null);
      return resultSummary(this.#existing(value), true);
    }
    if (!this.#env.D1_DATABASE || typeof this.#env.D1_DATABASE.prepare !== "function") throw new Error("d1_binding_not_configured");
    if (!this.#env.D1_EVIDENCE_BUCKET || typeof this.#env.D1_EVIDENCE_BUCKET.put !== "function") throw new Error("r2_evidence_binding_not_configured");

    this.#transactionSync(() => {
      const prepared = this.#coordinator.prepareAttempt({ ...value, operation: "prepare" });
      if (prepared.decision === "exact_replay") throw new Error("conflicting_replay");
      this.#coordinator.reserveDispatch({ ...value, operation: "reserve_dispatch" });
      this.#sql.exec("INSERT INTO provider_lifecycle_attempts (target_key_sha256, generation_sha256, operation_id_sha256, execution_attempt_id_sha256, provider_request_id_sha256, plan_sha256, consent_sha256, binding_sha256, phase, provider_calls, provider_effect) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'dispatch_reserved', NULL, 'unknown')", value.targetKeySha256, value.generationSha256, value.operationIdSha256, value.executionAttemptIdSha256, value.providerRequestIdSha256, value.planSha256, value.consentSha256, value.bindingSha256);
      const read = this.#existing(value);
      if (!read || read.phase !== "dispatch_reserved") throw new Error("dispatch_reservation_readback_mismatch");
    });

    let raw;
    try {
      // Exactly one provider invocation. This call is intentionally outside
      // transactionSync: network/provider I/O must never occur in a SQLite
      // transaction, and no retry is attempted here.
      raw = await this.#env.D1_DATABASE.prepare(value.sql).bind(...value.params).run();
    } catch {
      this.#markReconciliation(value, 1);
      return resultSummary(this.#existing(value));
    }

    let encoded;
    try {
      encoded = canonicalResponse(strictResult(raw, value.maxRows));
    } catch {
      this.#markReconciliation(value, 1);
      return resultSummary(this.#existing(value));
    }
    const responseBytes = new TextEncoder().encode(encoded);
    if (responseBytes.length > MAX_RESPONSE_BYTES) {
      this.#markReconciliation(value, 1);
      return resultSummary(this.#existing(value));
    }
    const responseSha256 = await hashBytes(responseBytes);
    const evidenceKey = `d1-lifecycle/${value.targetKeySha256}/${value.generationSha256}/${value.operationIdSha256}.json`;
    const effect = raw.meta.changed_db ? "one" : "zero";
    const evidenceKeySha256 = await hashBytes(new TextEncoder().encode(evidenceKey));
    const witnessSha256 = await hashBytes(new TextEncoder().encode([value.bindingSha256, responseSha256, String(responseBytes.length), evidenceKey, effect].join("|")));
    try {
      await this.#env.D1_EVIDENCE_BUCKET.put(evidenceKey, responseBytes, { httpMetadata: { contentType: "application/json" }, customMetadata: { responseSha256, bindingSha256: value.bindingSha256, witnessSha256 } });
    } catch {
      this.#markReconciliation(value, 1, { sha256: responseSha256, size: responseBytes.length });
      return resultSummary(this.#existing(value));
    }

    try {
      this.#transactionSync(() => {
        // Re-read after the awaited provider/R2 operations. A changed or
        // missing state is ambiguity, never permission to issue another call.
        const current = this.#existing(value);
        if (!current || current.phase !== "dispatch_reserved") throw new Error("post_fetch_state_ambiguous");
        this.#coordinator.observeResponse({ ...value, operation: "observe_response" });
        const terminalPhase = effect === "one" ? "applied" : "not_applied";
        this.#coordinator.closeAttempt({ ...value, phase: terminalPhase, adapterWitnessPresent: true });
        this.#sql.exec("UPDATE provider_lifecycle_attempts SET phase = ?, provider_calls = 1, provider_effect = ?, response_sha256 = ?, response_size_bytes = ?, evidence_key_sha256 = ?, witness_sha256 = ? WHERE target_key_sha256 = ? AND generation_sha256 = ? AND operation_id_sha256 = ? AND phase = 'dispatch_reserved'", terminalPhase, effect, responseSha256, responseBytes.length, evidenceKeySha256, witnessSha256, value.targetKeySha256, value.generationSha256, value.operationIdSha256);
        const read = this.#existing(value);
        if (!read || read.phase !== terminalPhase || read.witness_sha256 !== witnessSha256) throw new Error("terminal_cas_readback_mismatch");
      });
    } catch {
      this.#markReconciliation(value, 1, { sha256: responseSha256, size: responseBytes.length, evidenceKeySha256, witnessSha256 });
    }
    return resultSummary(this.#existing(value));
  }
}
