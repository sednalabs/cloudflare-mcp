import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import {
  D1RowWriteCoordinator,
  GENESIS_CONTRACT,
  PROTOCOL_VERSION,
} from "../src/index.js";

class SqliteStorage {
  constructor(database = new DatabaseSync(":memory:")) { this.database = database; }
  exec(query, ...bindings) {
    const statements = query.split(";").map((s) => s.trim()).filter(Boolean);
    let result;
    for (const statement of statements) {
      if (/^\s*select\b/i.test(statement)) {
        const rows = this.database.prepare(statement).all(...bindings);
        result = { toArray: () => rows };
      } else {
        this.database.prepare(statement).run(...bindings);
        result = { toArray: () => [] };
      }
    }
    return result ?? { toArray: () => [] };
  }
}

const h = (character) => character.repeat(64);
const base = {
  contract: GENESIS_CONTRACT,
  protocolVersion: PROTOCOL_VERSION,
  targetKeySha256: h("a"), generationSha256: h("b"),
  authoritySha256: h("c"), genesisSha256: h("d"),
};
const attempt = {
  ...base, planSha256: h("e"), operationIdSha256: h("1"),
  executionAttemptIdSha256: h("2"), providerRequestIdSha256: h("3"),
};

function initialized() {
  const storage = new SqliteStorage();
  const coordinator = new D1RowWriteCoordinator({ sql: storage });
  assert.equal(coordinator.initializeGenesis(base).decision, "new");
  return { storage, coordinator };
}

test("coordinates exact lifecycle and survives re-instantiation", () => {
  const { storage, coordinator } = initialized();
  assert.equal(coordinator.initializeGenesis(base).decision, "exact_replay");
  assert.equal(coordinator.prepareAttempt(attempt).phase, "prepared");
  assert.equal(coordinator.reserveDispatch(attempt).phase, "dispatch_reserved");
  assert.equal(coordinator.observeResponse(attempt).phase, "response_observed");
  assert.throws(() => coordinator.closeAttempt({ ...attempt, phase: "applied" }), /adapter_witness_required/);
  assert.equal(coordinator.closeAttempt({ ...attempt, phase: "applied", adapterWitnessPresent: true }).phase, "applied");
  const restarted = new D1RowWriteCoordinator({ sql: storage });
  const replay = restarted.prepareAttempt(attempt);
  assert.equal(replay.decision, "exact_replay");
  assert.equal(replay.phase, "applied");
});

test("denies conflicting replays, duplicate identities, and active contenders", () => {
  const { coordinator } = initialized();
  assert.equal(coordinator.prepareAttempt(attempt).decision, "new");
  assert.throws(() => coordinator.prepareAttempt({ ...attempt, planSha256: h("f") }), /conflicting_replay/);
  assert.throws(() => coordinator.prepareAttempt({ ...attempt, operationIdSha256: h("4"), executionAttemptIdSha256: h("4") }), /attempt_identities_must_be_distinct/);
  assert.throws(() => coordinator.prepareAttempt({ ...attempt, operationIdSha256: h("4") }), /conflicting_active_attempt/);
});

test("requires observed response and witness before terminal success", () => {
  const { coordinator } = initialized();
  assert.throws(() => coordinator.closeAttempt(null), /attempt_input_required/);
  assert.throws(() => coordinator.closeAttempt({ ...attempt, phase: "dispatch_reserved" }), /invalid_phase/);
  assert.equal(coordinator.prepareAttempt(attempt).phase, "prepared");
  assert.throws(() => coordinator.closeAttempt({ ...attempt, phase: "applied", adapterWitnessPresent: true }), /invalid_transition/);
  coordinator.reserveDispatch(attempt);
  assert.equal(coordinator.closeAttempt({ ...attempt, phase: "reconciliation_required" }).phase, "reconciliation_required");
  assert.equal(coordinator.closeAttempt({ ...attempt, phase: "reconciled", adapterWitnessPresent: true }).phase, "reconciled");
});
