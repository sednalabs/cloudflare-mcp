//! Guarded first-ledger bootstrap proof products.
//!
//! `tools` owns MCP registration and final mutation-audit projection. This
//! focused module owns the bounded bootstrap state machine: empty-target
//! inventory, approval digest, exactly one non-idempotent initializer dispatch,
//! stable readback, and reconciliation summaries.

use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::{Value, json};

use crate::cloudflare::client::{
    D1MigrationManifestWrite, D1MigrationReconciliationReadLifecycle,
    d1_migration_manifest_write_provider_result_cause,
    d1_migration_manifest_write_reconciliation_cause, d1_migration_reconciliation_only_cause,
};
use crate::d1_migration_lease::{
    D1MigrationLease, acquire_d1_migration_lease, d1_migration_lease_requirements,
    preflight_d1_migration_target_custody,
};
use crate::d1_migration_manifest::{
    D1_BOOTSTRAP_RESERVED_MIGRATION_FAMILY, D1ManifestLedgerRow, d1_migrations_table_init_sql,
    parse_d1_migration_ledger, parse_d1_migration_ledger_authority,
};
use crate::mutation::{MutationAuditSession, MutationPlan};
use crate::server::CloudflareMcp;
use crate::tools::{d1_applied_migrations_sql, sha256_bytes_hex, sha256_hex};

pub(crate) const D1_BOOTSTRAP_OPERATION: &str = "d1_bootstrap_migration_ledger";
pub(crate) const D1_BOOTSTRAP_LEASE_FAMILY: &str = D1_BOOTSTRAP_RESERVED_MIGRATION_FAMILY;

pub(crate) struct D1BootstrapExecutionInput {
    pub(crate) account_id: String,
    pub(crate) database_id: String,
    pub(crate) migrations_table: String,
    pub(crate) dry_run: bool,
    pub(crate) approved_plan_sha256: Option<String>,
}

pub(crate) fn d1_bootstrap_mutation_target(input: &D1BootstrapExecutionInput) -> Value {
    let initializer_sql = d1_migrations_table_init_sql(&input.migrations_table);
    json!({
        "target_key_sha256": sha256_bytes_hex(
            format!("{}\0{}", input.account_id, input.database_id).as_bytes()
        ),
        "migrations_table": input.migrations_table,
        "initializer_sql_sha256": sha256_hex(&initializer_sql),
        "initializer_sql_size_bytes": initializer_sql.len(),
        "supplied_plan_sha256": input.approved_plan_sha256,
        "computed_plan_sha256": Value::Null,
    })
}

pub(crate) fn d1_bootstrap_mutation_plan(input: &D1BootstrapExecutionInput) -> MutationPlan {
    let initializer_sql = d1_migrations_table_init_sql(&input.migrations_table);
    let initializer_sql_sha256 = sha256_hex(&initializer_sql);
    MutationPlan::new(D1_BOOTSTRAP_OPERATION)
        .step(
            "validate_exact_target_and_table_identity",
            false,
            d1_bootstrap_mutation_target(input),
        )
        .step(
            "read_stable_primary_empty_target_inventory",
            false,
            json!({"bounded_object_rows": 2}),
        )
        .step(
            "bind_exact_bootstrap_plan",
            false,
            json!({"initializer_sql_sha256": initializer_sql_sha256}),
        )
        .step(
            "ensure_d1_dml_custody_layout",
            true,
            json!({
                "target_key_sha256": sha256_bytes_hex(
                    format!("{}\0{}", input.account_id, input.database_id).as_bytes()
                ),
                "effect_scope": "local_custody_only",
                "provider_dispatch_authority": "none",
            }),
        )
        .step(
            "authorize_complete_d1_dml_custody",
            false,
            json!({
                "target_key_sha256": sha256_bytes_hex(
                    format!("{}\0{}", input.account_id, input.database_id).as_bytes()
                ),
                "binding": "migration_lease_payload",
            }),
        )
        .step(
            "persist_initializer_attempt_authority",
            true,
            json!({
                "dispatch_protocol": crate::d1_migration_lease::D1_BOOTSTRAP_INITIALIZER_DISPATCH_PROTOCOL,
                "initializer_sql_sha256": initializer_sql_sha256,
            }),
        )
        .step(
            "initialize_canonical_empty_migration_ledger_once",
            true,
            json!({"initializer_sql_sha256": initializer_sql_sha256}),
        )
        .step(
            "read_stable_post_write_schema_and_empty_ledger",
            false,
            json!({"migrations_table": input.migrations_table}),
        )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct D1BootstrapInventoryObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum D1BootstrapInventoryState {
    Empty,
    CanonicalLedger,
    Conflicting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1BootstrapInventory {
    state: D1BootstrapInventoryState,
    objects: Vec<D1BootstrapInventoryObject>,
}

impl D1BootstrapInventory {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn state(&self) -> D1BootstrapInventoryState {
        self.state
    }

    pub(crate) fn summary(&self) -> Value {
        json!({
            "state": match self.state {
                D1BootstrapInventoryState::Empty => "empty",
                D1BootstrapInventoryState::CanonicalLedger => "canonical_ledger_only",
                D1BootstrapInventoryState::Conflicting => "conflicting_objects",
            },
            "observed_object_count": self.objects.len(),
            "result_capped": self.objects.len() == 2,
        })
    }
}

/// SQLite persists the initializer without its `IF NOT EXISTS` clause and
/// trailing statement terminator. Bootstrap recovery accepts only this exact
/// installed product; the broader manifest reader's legacy Wrangler variants
/// are not bootstrap authority.
pub(crate) fn d1_bootstrap_installed_schema_sql(migrations_table: &str) -> String {
    d1_migrations_table_init_sql(migrations_table)
        .strip_suffix(';')
        .expect("canonical D1 migration-ledger initializer has a trailing semicolon")
        .replacen("CREATE TABLE IF NOT EXISTS", "CREATE TABLE", 1)
}

fn is_exact_d1_bootstrap_schema(
    objects: &[D1BootstrapInventoryObject],
    migrations_table: &str,
) -> bool {
    objects
        == [D1BootstrapInventoryObject {
            object_type: "table".to_string(),
            name: migrations_table.to_string(),
            table_name: migrations_table.to_string(),
            sql: Some(d1_bootstrap_installed_schema_sql(migrations_table)),
        }]
}

pub(crate) struct D1BootstrapReadFailure {
    pub(crate) result: CallToolResult,
    pub(crate) provider_calls: usize,
    read_evidence: Vec<Value>,
}

pub(crate) struct D1BootstrapPostState {
    pub(crate) inventory: D1BootstrapInventory,
    pub(crate) ledger: Vec<D1ManifestLedgerRow>,
    pub(crate) provider_calls: usize,
    read_evidence: Vec<Value>,
}

struct D1BootstrapStableRead<T> {
    value: T,
    provider_calls: usize,
    read_evidence: Vec<Value>,
}

#[derive(Clone, Copy)]
enum D1BootstrapReadWindow {
    DryRunPreflight,
    LivePredispatch,
    AmbiguousWriteReconciliation,
    PostWriteProof,
}

impl D1BootstrapReadWindow {
    const fn prefix(self) -> &'static str {
        match self {
            Self::DryRunPreflight => "dry_run_preflight",
            Self::LivePredispatch => "live_predispatch",
            Self::AmbiguousWriteReconciliation => "ambiguous_write_reconciliation",
            Self::PostWriteProof => "post_write_proof",
        }
    }

    fn phase(self, read: &'static str) -> String {
        format!("{}.{}", self.prefix(), read)
    }
}

fn bootstrap_error(
    code: &'static str,
    message: &'static str,
    hint: &'static str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": D1_BOOTSTRAP_OPERATION,
        "status": "blocked",
        "provider_mutations": 0,
        "error": {"code": code, "message": message, "hint": hint},
    }))
}

fn exact_read_evidence(
    phase: &str,
    sql: &str,
    lifecycle: &D1MigrationReconciliationReadLifecycle,
    response_body_sha256: Option<&str>,
    response_body_size_bytes: Option<usize>,
    parse_state: &'static str,
) -> Value {
    json!({
        "phase": phase,
        "query_sha256": sha256_hex(sql),
        "provider_call_attempted": lifecycle.dispatch_stage == "attempted",
        "lifecycle": lifecycle,
        "response": {
            "body_sha256": response_body_sha256,
            "body_size_bytes": response_body_size_bytes,
            "complete_body_digest": response_body_sha256.is_some()
                && lifecycle.body_stage == "completely_read",
            "parse_state": parse_state,
        },
    })
}

fn provider_read_lifecycle(read_evidence: &[Value]) -> Vec<Value> {
    read_evidence.to_vec()
}

fn response_evidence(read_evidence: &[Value]) -> Vec<Value> {
    read_evidence.to_vec()
}

fn call_tool_error_code(result: &CallToolResult) -> Option<&str> {
    result
        .structured_content
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str)
}

fn bootstrap_initializer_ambiguous_write_evidence(
    classification: &'static str,
    message: &'static str,
) -> Value {
    json!({
        "code": "d1.bootstrap_initializer_result_ambiguous",
        "classification": classification,
        "message": message,
        "retryable": false,
        "operator_guidance": "reconciliation_only",
    })
}

fn bootstrap_initializer_provider_result_cause(
    detail: &Value,
    write: &D1MigrationManifestWrite,
) -> Value {
    d1_migration_manifest_write_provider_result_cause(write, detail)
}

/// Validate the one DDL-only initializer acknowledgement without importing the
/// manifest migration contract's row-write requirement. D1 may truthfully
/// report zero changed rows for `CREATE TABLE`; exact schema and empty-ledger
/// effect proof comes from the separate stable primary post-readback.
pub(crate) fn validate_d1_bootstrap_initializer_write_result(value: &Value) -> Result<(), Value> {
    let result_sets = value.as_array().ok_or_else(|| {
        bootstrap_initializer_ambiguous_write_evidence(
            "missing_or_non_array_result",
            "provider initializer response did not contain a D1 result-set array",
        )
    })?;
    if result_sets.len() != 1 {
        return Err(bootstrap_initializer_ambiguous_write_evidence(
            "unexpected_result_set_count",
            "one initializer statement did not return exactly one D1 result set",
        ));
    }
    let result_set = result_sets[0].as_object().ok_or_else(|| {
        bootstrap_initializer_ambiguous_write_evidence(
            "malformed_result_set",
            "provider initializer result set was not an object",
        )
    })?;
    if result_set.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(bootstrap_initializer_ambiguous_write_evidence(
            "inner_statement_failure_or_missing_success",
            "provider initializer response did not prove statement success",
        ));
    }
    match result_set.get("errors") {
        Some(Value::Array(errors)) if !errors.is_empty() => {
            return Err(bootstrap_initializer_ambiguous_write_evidence(
                "inner_statement_error",
                "provider initializer response included an inner D1 statement error",
            ));
        }
        None | Some(Value::Array(_)) => {}
        _ => {
            return Err(bootstrap_initializer_ambiguous_write_evidence(
                "malformed_inner_errors",
                "provider initializer response contained a malformed inner errors value",
            ));
        }
    }
    if !matches!(result_set.get("results"), Some(Value::Array(results)) if results.is_empty()) {
        return Err(bootstrap_initializer_ambiguous_write_evidence(
            "unexpected_inner_results",
            "provider DDL initializer response did not contain an exact empty results array",
        ));
    }
    let meta = result_set
        .get("meta")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            bootstrap_initializer_ambiguous_write_evidence(
                "missing_or_malformed_write_metadata",
                "provider initializer response did not contain exact D1 mutation metadata",
            )
        })?;
    if meta.get("served_by_primary").and_then(Value::as_bool) != Some(true) {
        return Err(bootstrap_initializer_ambiguous_write_evidence(
            "write_not_served_by_primary",
            "provider initializer response did not explicitly prove primary service",
        ));
    }
    if meta.get("changed_db").and_then(Value::as_bool) != Some(true) {
        return Err(bootstrap_initializer_ambiguous_write_evidence(
            "database_change_not_acknowledged",
            "provider initializer response did not explicitly acknowledge a database change",
        ));
    }
    for field in ["changes", "rows_written"] {
        if meta.get(field).and_then(Value::as_u64).is_none() {
            return Err(bootstrap_initializer_ambiguous_write_evidence(
                "missing_or_malformed_write_metadata",
                "provider initializer response did not contain typed non-negative mutation counts",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn contextualize_bootstrap_failure(
    result: CallToolResult,
    input: &D1BootstrapExecutionInput,
    computed_plan_sha256: Option<&str>,
    provider_calls: usize,
    provider_mutations: usize,
    read_evidence: &[Value],
    lease: Option<&D1MigrationLease>,
    lease_retained: Option<bool>,
    provider_outcome: &'static str,
    reconciliation_evidence: Option<Value>,
) -> CallToolResult {
    let source = result.structured_content.unwrap_or_else(|| json!({}));
    let error = source.get("error").cloned().unwrap_or_else(|| {
        json!({
            "code": "d1.bootstrap_error",
            "message": "migration-ledger bootstrap failed",
            "hint": "Inspect the guarded bootstrap evidence before another attempt.",
        })
    });
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": D1_BOOTSTRAP_OPERATION,
        "status": if provider_mutations == 0 && lease_retained != Some(true) {
            "blocked"
        } else {
            "reconciliation_required"
        },
        "account_id": input.account_id,
        "database_id": input.database_id,
        "migrations_table": input.migrations_table,
        "supplied_plan_sha256": input.approved_plan_sha256,
        "computed_plan_sha256": computed_plan_sha256,
        "provider_calls": provider_calls,
        "provider_mutations": provider_mutations,
        "provider_outcome": provider_outcome,
        "lease_retained": lease_retained,
        "lease": lease.map(|lease| &lease.identity),
        "failure_evidence": {
            "target_inventory": source.get("target_inventory"),
            "ledger_row_count": source.get("ledger_row_count"),
        },
        "provider_read_lifecycle": provider_read_lifecycle(read_evidence),
        "response_evidence": response_evidence(read_evidence),
        "reconciliation_evidence": reconciliation_evidence,
        "automatic_retry_permitted": false,
        "operator_handoff": if provider_mutations == 0 && lease_retained != Some(true) {
            "No initializer SQL was dispatched. Correct the preflight or approval failure and run a fresh dry run before a live call."
        } else {
            "Do not retry bootstrap. Reconcile the exact provider state and retained custody evidence before any migration or bootstrap write."
        },
        "error": error,
    }))
}

/// Inspect at most two application-owned schema objects. SQLite internals and
/// Cloudflare's reserved `_cf_*` family are provider-owned and excluded by
/// both object and parent identity. Two rows are enough to distinguish the
/// only accepted products: no application objects before the bootstrap, or
/// exactly one canonical ledger table after it.
pub(crate) fn d1_bootstrap_inventory_sql() -> &'static str {
    "SELECT type, name, tbl_name, sql FROM sqlite_master \
     WHERE lower(name) NOT GLOB 'sqlite_*' \
       AND lower(name) NOT GLOB '_cf_*' \
       AND lower(tbl_name) NOT GLOB '_cf_*' \
     ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 WHEN 'view' THEN 2 WHEN 'trigger' THEN 3 ELSE 4 END, \
              name COLLATE BINARY, tbl_name COLLATE BINARY \
     LIMIT 2"
}

fn result_rows(value: &Value) -> Result<&Vec<Value>, CallToolResult> {
    let result_sets = if value.is_array() {
        value
    } else {
        let envelope = value.as_object().ok_or_else(|| {
            bootstrap_error(
                "d1.bootstrap_inventory_malformed",
                "provider inventory response was neither a result-set array nor an envelope object",
                "Re-read the independently selected empty D1 target from the primary before bootstrap.",
            )
        })?;
        if envelope.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(bootstrap_error(
                "d1.bootstrap_inventory_malformed",
                "provider inventory envelope did not explicitly prove success",
                "Re-read the independently selected empty D1 target from the primary before bootstrap.",
            ));
        }
        match envelope.get("errors") {
            None | Some(Value::Array(_))
                if envelope
                    .get("errors")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty) => {}
            _ => {
                return Err(bootstrap_error(
                    "d1.bootstrap_inventory_malformed",
                    "provider inventory envelope included contradictory or malformed errors",
                    "Reconcile the D1 read response before bootstrap.",
                ));
            }
        }
        envelope.get("result").ok_or_else(|| {
            bootstrap_error(
                "d1.bootstrap_inventory_malformed",
                "provider inventory envelope did not contain a result-set array",
                "Re-read the independently selected empty D1 target from the primary before bootstrap.",
            )
        })?
    };

    let result_set = result_sets
        .as_array()
        .and_then(|sets| (sets.len() == 1).then_some(&sets[0]))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            bootstrap_error(
                "d1.bootstrap_inventory_malformed",
                "provider inventory response did not contain exactly one result set",
                "Reconcile the D1 read response before bootstrap.",
            )
        })?;
    if result_set.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(bootstrap_error(
            "d1.bootstrap_inventory_malformed",
            "provider inventory result did not explicitly prove statement success",
            "Reconcile the D1 read response before bootstrap.",
        ));
    }
    match result_set.get("errors") {
        None | Some(Value::Array(_))
            if result_set
                .get("errors")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty) => {}
        _ => {
            return Err(bootstrap_error(
                "d1.bootstrap_inventory_malformed",
                "provider inventory result included contradictory or malformed errors",
                "Reconcile the D1 read response before bootstrap.",
            ));
        }
    }
    if result_set
        .get("meta")
        .and_then(Value::as_object)
        .and_then(|meta| meta.get("served_by_primary"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(bootstrap_error(
            "d1.bootstrap_inventory_not_primary",
            "provider inventory readback did not explicitly prove primary service",
            "Bootstrap only after a primary-served empty-target preflight.",
        ));
    }
    result_set
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            bootstrap_error(
                "d1.bootstrap_inventory_malformed",
                "provider inventory result did not contain a results array",
                "Reconcile the D1 read response before bootstrap.",
            )
        })
}

pub(crate) fn parse_d1_bootstrap_inventory(
    value: &Value,
    migrations_table: &str,
) -> Result<D1BootstrapInventory, CallToolResult> {
    let rows = result_rows(value)?;
    if rows.len() > 2 {
        return Err(bootstrap_error(
            "d1.bootstrap_inventory_malformed",
            "provider inventory returned more rows than the bounded query permits",
            "Reconcile the exact D1 schema before bootstrap.",
        ));
    }
    let mut objects = Vec::with_capacity(rows.len());
    for row in rows {
        let row = row.as_object().ok_or_else(|| {
            bootstrap_error(
                "d1.bootstrap_inventory_malformed",
                "provider inventory row was not an object",
                "Reconcile the exact D1 schema before bootstrap.",
            )
        })?;
        let object_type = row
            .get("type")
            .and_then(Value::as_str)
            .filter(|value| matches!(*value, "table" | "index" | "view" | "trigger"))
            .ok_or_else(|| {
                bootstrap_error(
                    "d1.bootstrap_inventory_malformed",
                    "provider inventory row had an unsupported object type",
                    "Reconcile the exact D1 schema before bootstrap.",
                )
            })?;
        let text_field = |name: &str| {
            row.get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 255 && !value.contains('\0'))
                .map(str::to_string)
                .ok_or_else(|| {
                    bootstrap_error(
                        "d1.bootstrap_inventory_malformed",
                        "provider inventory row had a malformed object identity",
                        "Reconcile the exact D1 schema before bootstrap.",
                    )
                })
        };
        if row.len() != 4 {
            return Err(bootstrap_error(
                "d1.bootstrap_inventory_malformed",
                "provider inventory row did not match the exact four-field projection",
                "Reconcile the exact D1 schema before bootstrap.",
            ));
        }
        let sql = match row.get("sql") {
            Some(Value::String(value)) if value.len() <= 1024 * 1024 && !value.contains('\0') => {
                Some(value.clone())
            }
            Some(Value::Null) => None,
            _ => {
                return Err(bootstrap_error(
                    "d1.bootstrap_inventory_malformed",
                    "provider inventory row had malformed SQL evidence",
                    "Reconcile the exact D1 schema before bootstrap.",
                ));
            }
        };
        objects.push(D1BootstrapInventoryObject {
            object_type: object_type.to_string(),
            name: text_field("name")?,
            table_name: text_field("tbl_name")?,
            sql,
        });
    }

    let state = if objects.is_empty() {
        D1BootstrapInventoryState::Empty
    } else if parse_d1_migration_ledger_authority(value, migrations_table).is_ok()
        && is_exact_d1_bootstrap_schema(&objects, migrations_table)
    {
        D1BootstrapInventoryState::CanonicalLedger
    } else {
        D1BootstrapInventoryState::Conflicting
    };
    Ok(D1BootstrapInventory { state, objects })
}

async fn read_inventory_once(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    phase: &str,
) -> Result<D1BootstrapStableRead<D1BootstrapInventory>, D1BootstrapReadFailure> {
    let sql = d1_bootstrap_inventory_sql();
    match server
        .cloudflare
        .query_d1_migration_reconciliation_batch(account_id, database_id, sql)
        .await
    {
        Ok(batch) => {
            let provider_calls = batch.lifecycle.provider_calls();
            match parse_d1_bootstrap_inventory(&batch.result, migrations_table) {
                Ok(value) => Ok(D1BootstrapStableRead {
                    value,
                    provider_calls,
                    read_evidence: vec![exact_read_evidence(
                        phase,
                        sql,
                        &batch.lifecycle,
                        Some(&batch.response_body_sha256),
                        Some(batch.response_body_size_bytes),
                        "decoded",
                    )],
                }),
                Err(cause) => Err(D1BootstrapReadFailure {
                    result: CallToolResult::structured_error(json!({
                        "ok": false,
                        "operation": D1_BOOTSTRAP_OPERATION,
                        "status": "blocked",
                        "provider_mutations": 0,
                        "error": {
                            "code": "d1.bootstrap_inventory_malformed",
                            "message": "the bounded empty-target inventory response was malformed or not primary-served",
                            "hint": "Reconcile the exact provider evidence before bootstrap.",
                            "cause_code": call_tool_error_code(&cause),
                        },
                    })),
                    provider_calls,
                    read_evidence: vec![exact_read_evidence(
                        phase,
                        sql,
                        &batch.lifecycle,
                        Some(&batch.response_body_sha256),
                        Some(batch.response_body_size_bytes),
                        "malformed",
                    )],
                }),
            }
        }
        Err(failure) => {
            let provider_calls = failure.lifecycle.provider_calls();
            Err(D1BootstrapReadFailure {
                result: CallToolResult::structured_error(json!({
                "ok": false,
                "operation": D1_BOOTSTRAP_OPERATION,
                "status": "blocked",
                "provider_mutations": 0,
                "error": {
                    "code": "d1.bootstrap_inventory_unreadable",
                    "message": "the bounded empty-target inventory response was unavailable or contradictory",
                    "hint": "Reconcile target access and exact provider evidence before bootstrap.",
                    "cause": d1_migration_reconciliation_only_cause(&failure.error),
                },
                })),
                provider_calls,
                read_evidence: vec![exact_read_evidence(
                    phase,
                    sql,
                    &failure.lifecycle,
                    failure.response_body_sha256.as_deref(),
                    failure.response_body_size_bytes,
                    "unavailable",
                )],
            })
        }
    }
}

async fn read_stable_d1_bootstrap_inventory(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    window: D1BootstrapReadWindow,
) -> Result<D1BootstrapStableRead<D1BootstrapInventory>, D1BootstrapReadFailure> {
    let first_phase = window.phase("inventory.first");
    let first = read_inventory_once(
        server,
        account_id,
        database_id,
        migrations_table,
        &first_phase,
    )
    .await?;
    let second_phase = window.phase("inventory.second");
    let second = read_inventory_once(
        server,
        account_id,
        database_id,
        migrations_table,
        &second_phase,
    )
    .await
    .map_err(|mut failure| {
        failure.provider_calls += first.provider_calls;
        let mut evidence = first.read_evidence.clone();
        evidence.extend(failure.read_evidence);
        failure.read_evidence = evidence;
        failure
    })?;
    let provider_calls = first.provider_calls + second.provider_calls;
    let mut read_evidence = first.read_evidence;
    read_evidence.extend(second.read_evidence);
    if first.value != second.value {
        return Err(D1BootstrapReadFailure {
            result: bootstrap_error(
                "d1.bootstrap_inventory_unstable",
                "two exact one-attempt primary empty-target inventory readbacks disagreed",
                "Reconcile concurrent or external schema activity before bootstrap.",
            ),
            provider_calls,
            read_evidence,
        });
    }
    Ok(D1BootstrapStableRead {
        value: first.value,
        provider_calls,
        read_evidence,
    })
}

pub(crate) fn require_empty_d1_bootstrap_inventory(
    inventory: D1BootstrapInventory,
) -> Result<D1BootstrapInventory, CallToolResult> {
    if inventory.state == D1BootstrapInventoryState::Empty {
        return Ok(inventory);
    }
    Err(CallToolResult::structured_error(json!({
        "ok": false,
        "operation": D1_BOOTSTRAP_OPERATION,
        "status": "blocked",
        "provider_mutations": 0,
        "target_inventory": inventory.summary(),
        "error": {
            "code": "d1.bootstrap_target_not_empty",
            "message": "the selected D1 target already contains a ledger or application object",
            "hint": "Select an independently provisioned empty D1 target. Do not bootstrap over existing objects.",
        },
    })))
}

async fn read_ledger_once(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    phase: &str,
) -> Result<D1BootstrapStableRead<Vec<D1ManifestLedgerRow>>, D1BootstrapReadFailure> {
    let sql = d1_applied_migrations_sql(migrations_table);
    match server
        .cloudflare
        .query_d1_migration_reconciliation_batch(account_id, database_id, &sql)
        .await
    {
        Ok(batch) => {
            let provider_calls = batch.lifecycle.provider_calls();
            match parse_d1_migration_ledger(&batch.result) {
                Ok(value) => Ok(D1BootstrapStableRead {
                    value,
                    provider_calls,
                    read_evidence: vec![exact_read_evidence(
                        phase,
                        &sql,
                        &batch.lifecycle,
                        Some(&batch.response_body_sha256),
                        Some(batch.response_body_size_bytes),
                        "decoded",
                    )],
                }),
                Err(cause) => Err(D1BootstrapReadFailure {
                    result: CallToolResult::structured_error(json!({
                        "ok": false,
                        "operation": D1_BOOTSTRAP_OPERATION,
                        "status": "reconciliation_required",
                        "error": {
                            "code": "d1.bootstrap_ledger_malformed",
                            "message": "initialized migration-ledger readback was malformed or not primary-served",
                            "hint": "Retain custody and reconcile the exact provider state; do not retry bootstrap.",
                            "cause_code": call_tool_error_code(&cause),
                        },
                    })),
                    provider_calls,
                    read_evidence: vec![exact_read_evidence(
                        phase,
                        &sql,
                        &batch.lifecycle,
                        Some(&batch.response_body_sha256),
                        Some(batch.response_body_size_bytes),
                        "malformed",
                    )],
                }),
            }
        }
        Err(failure) => {
            let provider_calls = failure.lifecycle.provider_calls();
            Err(D1BootstrapReadFailure {
                result: CallToolResult::structured_error(json!({
                "ok": false,
                "operation": D1_BOOTSTRAP_OPERATION,
                "status": "reconciliation_required",
                "error": {
                    "code": "d1.bootstrap_ledger_unreadable",
                    "message": "the bounded initialized-ledger response was unavailable or contradictory",
                    "hint": "Retain custody and reconcile the exact provider state; do not retry bootstrap.",
                    "cause": d1_migration_reconciliation_only_cause(&failure.error),
                },
                })),
                provider_calls,
                read_evidence: vec![exact_read_evidence(
                    phase,
                    &sql,
                    &failure.lifecycle,
                    failure.response_body_sha256.as_deref(),
                    failure.response_body_size_bytes,
                    "unavailable",
                )],
            })
        }
    }
}

async fn read_stable_empty_d1_bootstrap_ledger(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    window: D1BootstrapReadWindow,
) -> Result<D1BootstrapStableRead<Vec<D1ManifestLedgerRow>>, D1BootstrapReadFailure> {
    let first_phase = window.phase("ledger.first");
    let first = read_ledger_once(
        server,
        account_id,
        database_id,
        migrations_table,
        &first_phase,
    )
    .await?;
    let second_phase = window.phase("ledger.second");
    let second = read_ledger_once(
        server,
        account_id,
        database_id,
        migrations_table,
        &second_phase,
    )
    .await
    .map_err(|mut failure| {
        failure.provider_calls += first.provider_calls;
        let mut evidence = first.read_evidence.clone();
        evidence.extend(failure.read_evidence);
        failure.read_evidence = evidence;
        failure
    })?;
    let provider_calls = first.provider_calls + second.provider_calls;
    let mut read_evidence = first.read_evidence;
    read_evidence.extend(second.read_evidence);
    if first.value != second.value {
        return Err(D1BootstrapReadFailure {
            result: bootstrap_error(
                "d1.bootstrap_ledger_unstable",
                "two exact one-attempt primary initialized-ledger readbacks disagreed",
                "Retain custody and reconcile the exact provider state; do not retry bootstrap.",
            ),
            provider_calls,
            read_evidence,
        });
    }
    if !first.value.is_empty() {
        return Err(D1BootstrapReadFailure {
            result: CallToolResult::structured_error(json!({
                "ok": false,
                "operation": D1_BOOTSTRAP_OPERATION,
                "status": "reconciliation_required",
                "ledger_row_count": first.value.len(),
                "error": {
                    "code": "d1.bootstrap_ledger_not_empty",
                    "message": "the initialized migration ledger was not empty",
                    "hint": "Retain custody and reconcile unexpected migration activity; do not retry bootstrap.",
                },
            })),
            provider_calls,
            read_evidence,
        });
    }
    Ok(D1BootstrapStableRead {
        value: first.value,
        provider_calls,
        read_evidence,
    })
}

pub(crate) async fn read_stable_d1_bootstrap_post_state(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
) -> Result<D1BootstrapPostState, D1BootstrapReadFailure> {
    let inventory_read = read_stable_d1_bootstrap_inventory(
        server,
        account_id,
        database_id,
        migrations_table,
        D1BootstrapReadWindow::PostWriteProof,
    )
    .await?;
    if inventory_read.value.state != D1BootstrapInventoryState::CanonicalLedger {
        return Err(D1BootstrapReadFailure {
            result: CallToolResult::structured_error(json!({
                "ok": false,
                "operation": D1_BOOTSTRAP_OPERATION,
                "status": "reconciliation_required",
                "target_inventory": inventory_read.value.summary(),
                "error": {
                    "code": "d1.bootstrap_post_schema_invalid",
                    "message": "post-write readback did not prove exactly one canonical migration-ledger table and no application objects",
                    "hint": "Retain custody and reconcile the exact provider schema; do not retry bootstrap.",
                },
            })),
            provider_calls: inventory_read.provider_calls,
            read_evidence: inventory_read.read_evidence,
        });
    }
    match read_stable_empty_d1_bootstrap_ledger(
        server,
        account_id,
        database_id,
        migrations_table,
        D1BootstrapReadWindow::PostWriteProof,
    )
    .await
    {
        Ok(ledger_read) => {
            let mut read_evidence = inventory_read.read_evidence;
            read_evidence.extend(ledger_read.read_evidence);
            Ok(D1BootstrapPostState {
                inventory: inventory_read.value,
                ledger: ledger_read.value,
                provider_calls: inventory_read.provider_calls + ledger_read.provider_calls,
                read_evidence,
            })
        }
        Err(mut failure) => {
            failure.provider_calls += inventory_read.provider_calls;
            let mut read_evidence = inventory_read.read_evidence;
            read_evidence.extend(failure.read_evidence);
            failure.read_evidence = read_evidence;
            Err(failure)
        }
    }
}

/// Read-only post-dispatch evidence never authorizes replay. It is deliberately
/// compact and never returns object names or SQL text.
pub(crate) async fn d1_bootstrap_reconciliation_evidence(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
) -> (Value, usize, Vec<Value>) {
    match read_stable_d1_bootstrap_inventory(
        server,
        account_id,
        database_id,
        migrations_table,
        D1BootstrapReadWindow::AmbiguousWriteReconciliation,
    )
    .await
    {
        Err(failure) => (
            json!({
                "state": "unverified",
                "reason": call_tool_error_code(&failure.result),
                "effect_attribution": "unknown",
                "provider_read_lifecycle": provider_read_lifecycle(&failure.read_evidence),
                "response_evidence": response_evidence(&failure.read_evidence),
            }),
            failure.provider_calls,
            failure.read_evidence,
        ),
        Ok(inventory_read) => match inventory_read.value.state {
            D1BootstrapInventoryState::Empty => (
                json!({
                    "state": "ledger_absent",
                    "target_inventory": inventory_read.value.summary(),
                    "effect_attribution": "unknown",
                    "provider_read_lifecycle": provider_read_lifecycle(&inventory_read.read_evidence),
                    "response_evidence": response_evidence(&inventory_read.read_evidence),
                }),
                inventory_read.provider_calls,
                inventory_read.read_evidence,
            ),
            D1BootstrapInventoryState::Conflicting => (
                json!({
                    "state": "conflicting_objects",
                    "target_inventory": inventory_read.value.summary(),
                    "effect_attribution": "unknown",
                    "provider_read_lifecycle": provider_read_lifecycle(&inventory_read.read_evidence),
                    "response_evidence": response_evidence(&inventory_read.read_evidence),
                }),
                inventory_read.provider_calls,
                inventory_read.read_evidence,
            ),
            D1BootstrapInventoryState::CanonicalLedger => {
                match read_stable_empty_d1_bootstrap_ledger(
                    server,
                    account_id,
                    database_id,
                    migrations_table,
                    D1BootstrapReadWindow::AmbiguousWriteReconciliation,
                )
                .await
                {
                    Ok(ledger_read) => {
                        let mut read_evidence = inventory_read.read_evidence;
                        read_evidence.extend(ledger_read.read_evidence);
                        (
                            json!({
                                "state": "canonical_empty_ledger_observed",
                                "target_inventory": inventory_read.value.summary(),
                                "ledger_row_count": ledger_read.value.len(),
                                "effect_attribution": "unknown",
                                "provider_read_lifecycle": provider_read_lifecycle(&read_evidence),
                                "response_evidence": response_evidence(&read_evidence),
                            }),
                            inventory_read.provider_calls + ledger_read.provider_calls,
                            read_evidence,
                        )
                    }
                    Err(failure) => {
                        let mut read_evidence = inventory_read.read_evidence;
                        read_evidence.extend(failure.read_evidence);
                        (
                            json!({
                                "state": "ledger_unverified",
                                "target_inventory": inventory_read.value.summary(),
                                "reason": call_tool_error_code(&failure.result),
                                "effect_attribution": "unknown",
                                "provider_read_lifecycle": provider_read_lifecycle(&read_evidence),
                                "response_evidence": response_evidence(&read_evidence),
                            }),
                            inventory_read.provider_calls + failure.provider_calls,
                            read_evidence,
                        )
                    }
                }
            }
        },
    }
}

pub(crate) fn d1_bootstrap_plan_sha256(
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    initializer_sql: &str,
) -> String {
    #[derive(Serialize)]
    struct Plan<'a> {
        version: u8,
        operation: &'static str,
        account_id: &'a str,
        database_id: &'a str,
        migrations_table: &'a str,
        required_preflight_state: &'static str,
        initializer_sql_sha256: String,
        initializer_sql_size_bytes: usize,
    }
    let bytes = serde_json::to_vec(&Plan {
        version: 1,
        operation: D1_BOOTSTRAP_OPERATION,
        account_id,
        database_id,
        migrations_table,
        required_preflight_state: "empty_application_schema",
        initializer_sql_sha256: sha256_hex(initializer_sql),
        initializer_sql_size_bytes: initializer_sql.len(),
    })
    .expect("serializing the D1 bootstrap plan is infallible");
    sha256_bytes_hex(&bytes)
}

pub(crate) fn d1_bootstrap_plan_matches(provided: Option<&str>, expected: &str) -> bool {
    provided
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .is_some_and(|value| value == expected)
}

pub(crate) async fn execute_d1_bootstrap_migration_ledger(
    server: &CloudflareMcp,
    input: D1BootstrapExecutionInput,
    audit: &mut MutationAuditSession,
) -> CallToolResult {
    let initializer_sql = d1_migrations_table_init_sql(&input.migrations_table);
    let initializer_sql_sha256 = sha256_hex(&initializer_sql);
    let mut provider_calls = 0_usize;
    let mut provider_mutations = 0_usize;
    let mut read_evidence = Vec::new();

    if input.dry_run {
        let inventory = match read_stable_d1_bootstrap_inventory(
            server,
            &input.account_id,
            &input.database_id,
            &input.migrations_table,
            D1BootstrapReadWindow::DryRunPreflight,
        )
        .await
        {
            Ok(inventory_read) => {
                provider_calls += inventory_read.provider_calls;
                read_evidence.extend(inventory_read.read_evidence);
                inventory_read.value
            }
            Err(failure) => {
                provider_calls += failure.provider_calls;
                read_evidence.extend(failure.read_evidence);
                return contextualize_bootstrap_failure(
                    failure.result,
                    &input,
                    None,
                    provider_calls,
                    provider_mutations,
                    &read_evidence,
                    None,
                    Some(false),
                    "not_dispatched",
                    None,
                );
            }
        };
        let inventory = match require_empty_d1_bootstrap_inventory(inventory) {
            Ok(inventory) => inventory,
            Err(result) => {
                return contextualize_bootstrap_failure(
                    result,
                    &input,
                    None,
                    provider_calls,
                    provider_mutations,
                    &read_evidence,
                    None,
                    Some(false),
                    "not_dispatched",
                    None,
                );
            }
        };
        let plan_sha256 = d1_bootstrap_plan_sha256(
            &input.account_id,
            &input.database_id,
            &input.migrations_table,
            &initializer_sql,
        );
        audit.set_target(json!({
            "target_key_sha256": sha256_bytes_hex(
                format!("{}\0{}", input.account_id, input.database_id).as_bytes()
            ),
            "migrations_table": input.migrations_table,
            "initializer_sql_sha256": initializer_sql_sha256,
            "initializer_sql_size_bytes": initializer_sql.len(),
            "supplied_plan_sha256": input.approved_plan_sha256,
            "computed_plan_sha256": plan_sha256,
        }));
        return CallToolResult::structured(json!({
            "ok": true,
            "operation": D1_BOOTSTRAP_OPERATION,
            "status": "previewed",
            "account_id": input.account_id,
            "database_id": input.database_id,
            "migrations_table": input.migrations_table,
            "target_inventory": inventory.summary(),
            "initializer": {
                "sql_sha256": initializer_sql_sha256,
                "sql_size_bytes": initializer_sql.len(),
                "creates_only": "canonical_empty_migration_ledger",
            },
            "plan_sha256": plan_sha256,
            "provider_calls": provider_calls,
            "provider_mutations": provider_mutations,
            "provider_read_lifecycle": provider_read_lifecycle(&read_evidence),
            "response_evidence": response_evidence(&read_evidence),
            "lease": d1_migration_lease_requirements(
                &input.account_id,
                &input.database_id,
                D1_BOOTSTRAP_LEASE_FAMILY,
            ),
            "automatic_retry_permitted": false,
            "dry_run_note": "Two matching primary-served bounded schema reads proved no application-owned objects. SQLite and Cloudflare-managed internals were excluded. No D1 write was issued. A live call repeats this preflight under shared target custody and requires this exact plan_sha256.",
        }));
    }

    if let Err(result) =
        preflight_d1_migration_target_custody(&input.account_id, &input.database_id)
    {
        return contextualize_bootstrap_failure(
            result,
            &input,
            None,
            provider_calls,
            provider_mutations,
            &read_evidence,
            None,
            Some(false),
            "not_dispatched",
            None,
        );
    }
    let mut lease = match acquire_d1_migration_lease(
        &input.account_id,
        &input.database_id,
        D1_BOOTSTRAP_LEASE_FAMILY,
        input.approved_plan_sha256.as_deref(),
    ) {
        Ok(lease) => lease,
        Err(result) => {
            return contextualize_bootstrap_failure(
                result,
                &input,
                None,
                provider_calls,
                provider_mutations,
                &read_evidence,
                None,
                Some(false),
                "not_dispatched",
                None,
            );
        }
    };
    if let Err(result) = lease.revalidate() {
        return contextualize_bootstrap_failure(
            result,
            &input,
            None,
            provider_calls,
            provider_mutations,
            &read_evidence,
            Some(&lease),
            None,
            "not_dispatched",
            None,
        );
    }

    let inventory = match read_stable_d1_bootstrap_inventory(
        server,
        &input.account_id,
        &input.database_id,
        &input.migrations_table,
        D1BootstrapReadWindow::LivePredispatch,
    )
    .await
    {
        Ok(inventory_read) => {
            provider_calls += inventory_read.provider_calls;
            read_evidence.extend(inventory_read.read_evidence);
            inventory_read.value
        }
        Err(failure) => {
            provider_calls += failure.provider_calls;
            read_evidence.extend(failure.read_evidence);
            let result = failure.result;
            return match lease.release() {
                Ok(()) => contextualize_bootstrap_failure(
                    result,
                    &input,
                    None,
                    provider_calls,
                    provider_mutations,
                    &read_evidence,
                    Some(&lease),
                    Some(false),
                    "not_dispatched",
                    None,
                ),
                Err(release) => contextualize_bootstrap_failure(
                    release,
                    &input,
                    None,
                    provider_calls,
                    provider_mutations,
                    &read_evidence,
                    Some(&lease),
                    Some(true),
                    "not_dispatched",
                    None,
                ),
            };
        }
    };
    let inventory = match require_empty_d1_bootstrap_inventory(inventory) {
        Ok(inventory) => inventory,
        Err(result) => {
            return match lease.release() {
                Ok(()) => contextualize_bootstrap_failure(
                    result,
                    &input,
                    None,
                    provider_calls,
                    provider_mutations,
                    &read_evidence,
                    Some(&lease),
                    Some(false),
                    "not_dispatched",
                    None,
                ),
                Err(release) => contextualize_bootstrap_failure(
                    release,
                    &input,
                    None,
                    provider_calls,
                    provider_mutations,
                    &read_evidence,
                    Some(&lease),
                    Some(true),
                    "not_dispatched",
                    None,
                ),
            };
        }
    };
    let plan_sha256 = d1_bootstrap_plan_sha256(
        &input.account_id,
        &input.database_id,
        &input.migrations_table,
        &initializer_sql,
    );
    audit.set_target(json!({
        "target_key_sha256": sha256_bytes_hex(
            format!("{}\0{}", input.account_id, input.database_id).as_bytes()
        ),
        "migrations_table": input.migrations_table,
        "initializer_sql_sha256": initializer_sql_sha256,
        "initializer_sql_size_bytes": initializer_sql.len(),
        "supplied_plan_sha256": input.approved_plan_sha256,
        "computed_plan_sha256": plan_sha256,
    }));
    if !d1_bootstrap_plan_matches(input.approved_plan_sha256.as_deref(), &plan_sha256) {
        let mismatch = CallToolResult::structured_error(json!({
            "ok": false,
            "operation": D1_BOOTSTRAP_OPERATION,
            "error": {
                "code": "d1.bootstrap_plan_digest_mismatch",
                "message": "live bootstrap requires the exact lowercase plan_sha256 from a current successful empty-target dry run",
                "hint": "Run dry_run=true again and approve that exact digest for one live bootstrap call.",
            },
        }));
        return match lease.release() {
            Ok(()) => contextualize_bootstrap_failure(
                mismatch,
                &input,
                Some(&plan_sha256),
                provider_calls,
                provider_mutations,
                &read_evidence,
                Some(&lease),
                Some(false),
                "not_dispatched",
                None,
            ),
            Err(release) => contextualize_bootstrap_failure(
                release,
                &input,
                Some(&plan_sha256),
                provider_calls,
                provider_mutations,
                &read_evidence,
                Some(&lease),
                Some(true),
                "not_dispatched",
                None,
            ),
        };
    }
    if let Err(result) = lease.revalidate() {
        return contextualize_bootstrap_failure(
            result,
            &input,
            Some(&plan_sha256),
            provider_calls,
            provider_mutations,
            &read_evidence,
            Some(&lease),
            None,
            "not_dispatched",
            None,
        );
    }

    if let Err(result) = lease.record_bootstrap_initializer_attempt() {
        let lease_retained = if lease.revalidate().is_ok() {
            lease.retain();
            Some(true)
        } else {
            None
        };
        return contextualize_bootstrap_failure(
            result,
            &input,
            Some(&plan_sha256),
            provider_calls,
            provider_mutations,
            &read_evidence,
            Some(&lease),
            lease_retained,
            "not_dispatched",
            None,
        );
    }

    let write_result = match server
        .cloudflare
        .execute_d1_migration_manifest_write(
            &input.account_id,
            &input.database_id,
            &initializer_sql,
            &[],
        )
        .await
    {
        Ok(write) => {
            provider_calls += write.lifecycle.provider_calls();
            provider_mutations += write.lifecycle.provider_calls();
            validate_d1_bootstrap_initializer_write_result(&write.result)
                .map_err(|detail| bootstrap_initializer_provider_result_cause(&detail, &write))
        }
        Err(failure) => {
            provider_calls += failure.lifecycle.provider_calls();
            provider_mutations += failure.lifecycle.provider_calls();
            Err(json!({
                "kind": "transport",
                "detail": d1_migration_manifest_write_reconciliation_cause(&failure),
            }))
        }
    };
    if let Err(cause) = write_result {
        let (reconciliation, calls, reconciliation_read_evidence) =
            d1_bootstrap_reconciliation_evidence(
                server,
                &input.account_id,
                &input.database_id,
                &input.migrations_table,
            )
            .await;
        provider_calls += calls;
        read_evidence.extend(reconciliation_read_evidence);
        let result = CallToolResult::structured_error(json!({
            "ok": false,
            "operation": D1_BOOTSTRAP_OPERATION,
            "error": {
                "code": "d1.bootstrap_initializer_outcome_unknown",
                "message": "the one non-idempotent initializer dispatch did not return complete mutation proof",
                "hint": "Do not retry. Reconcile the exact provider state and retained target custody.",
                "cause": cause,
            },
        }));
        if lease.revalidate().is_ok() {
            lease.retain();
            return contextualize_bootstrap_failure(
                result,
                &input,
                Some(&plan_sha256),
                provider_calls,
                provider_mutations,
                &read_evidence,
                Some(&lease),
                Some(true),
                "unknown",
                Some(reconciliation),
            );
        }
        return contextualize_bootstrap_failure(
            result,
            &input,
            Some(&plan_sha256),
            provider_calls,
            provider_mutations,
            &read_evidence,
            Some(&lease),
            None,
            "unknown",
            Some(reconciliation),
        );
    }

    let post_state = match read_stable_d1_bootstrap_post_state(
        server,
        &input.account_id,
        &input.database_id,
        &input.migrations_table,
    )
    .await
    {
        Ok(post_state) => {
            provider_calls += post_state.provider_calls;
            read_evidence.extend(post_state.read_evidence.clone());
            post_state
        }
        Err(failure) => {
            provider_calls += failure.provider_calls;
            read_evidence.extend(failure.read_evidence);
            let lease_retained = if lease.revalidate().is_ok() {
                lease.retain();
                Some(true)
            } else {
                None
            };
            return contextualize_bootstrap_failure(
                failure.result,
                &input,
                Some(&plan_sha256),
                provider_calls,
                provider_mutations,
                &read_evidence,
                Some(&lease),
                lease_retained,
                "initializer_acknowledged_post_state_unproven",
                None,
            );
        }
    };
    if let Err(result) = lease.revalidate() {
        return contextualize_bootstrap_failure(
            result,
            &input,
            Some(&plan_sha256),
            provider_calls,
            provider_mutations,
            &read_evidence,
            Some(&lease),
            None,
            "applied_proven",
            None,
        );
    }
    if let Err(result) = lease.release() {
        return contextualize_bootstrap_failure(
            result,
            &input,
            Some(&plan_sha256),
            provider_calls,
            provider_mutations,
            &read_evidence,
            Some(&lease),
            Some(true),
            "applied_proven",
            None,
        );
    }
    CallToolResult::structured(json!({
        "ok": true,
        "operation": D1_BOOTSTRAP_OPERATION,
        "status": "applied_proven",
        "account_id": input.account_id,
        "database_id": input.database_id,
        "migrations_table": input.migrations_table,
        "supplied_plan_sha256": input.approved_plan_sha256,
        "computed_plan_sha256": plan_sha256,
        "target_preflight": inventory.summary(),
        "initializer": {
            "sql_sha256": initializer_sql_sha256,
            "sql_size_bytes": initializer_sql.len(),
            "provider_mutation_acknowledged": true,
        },
        "post_write": {
            "target_inventory": post_state.inventory.summary(),
            "ledger_row_count": post_state.ledger.len(),
            "stable_primary_schema_readback": true,
            "stable_primary_empty_ledger_readback": true,
        },
        "provider_calls": provider_calls,
        "provider_mutations": provider_mutations,
        "provider_read_lifecycle": provider_read_lifecycle(&read_evidence),
        "response_evidence": response_evidence(&read_evidence),
        "lease": d1_migration_lease_requirements(
            &input.account_id,
            &input.database_id,
            D1_BOOTSTRAP_LEASE_FAMILY,
        ),
        "automatic_retry_permitted": false,
        "migration_sql_executed": false,
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        D1BootstrapInventoryState, D1MigrationManifestWrite,
        bootstrap_initializer_provider_result_cause, d1_bootstrap_inventory_sql,
        d1_bootstrap_plan_matches, d1_bootstrap_plan_sha256, parse_d1_bootstrap_inventory,
        validate_d1_bootstrap_initializer_write_result,
    };
    use crate::cloudflare::client::D1MigrationManifestWriteLifecycle;
    use crate::d1_migration_manifest::d1_migrations_table_init_sql;

    fn response(results: Value, primary: Value) -> Value {
        json!([{
            "success": true,
            "errors": [],
            "results": results,
            "meta": {"served_by_primary": primary},
        }])
    }

    #[test]
    fn inventory_query_is_bounded_and_excludes_provider_internal_objects() {
        let sql = d1_bootstrap_inventory_sql();
        assert!(sql.contains("lower(name) NOT GLOB 'sqlite_*'"));
        assert!(sql.contains("lower(name) NOT GLOB '_cf_*'"));
        assert!(sql.contains("lower(tbl_name) NOT GLOB '_cf_*'"));
        assert!(sql.ends_with("LIMIT 2"));
    }

    #[test]
    fn inventory_classifies_empty_canonical_and_conflicting_products() {
        let empty =
            parse_d1_bootstrap_inventory(&response(json!([]), json!(true)), "d1_migrations")
                .expect("empty inventory");
        assert_eq!(empty.state(), D1BootstrapInventoryState::Empty);

        let initializer = d1_migrations_table_init_sql("d1_migrations");
        let installed = initializer
            .strip_suffix(';')
            .expect("initializer semicolon")
            .replacen("CREATE TABLE IF NOT EXISTS", "CREATE TABLE", 1);
        let canonical = parse_d1_bootstrap_inventory(
            &response(
                json!([{
                    "type": "table",
                    "name": "d1_migrations",
                    "tbl_name": "d1_migrations",
                    "sql": installed,
                }]),
                json!(true),
            ),
            "d1_migrations",
        )
        .expect("canonical inventory");
        assert_eq!(
            canonical.state(),
            D1BootstrapInventoryState::CanonicalLedger
        );

        let broader_wrangler_schema = parse_d1_bootstrap_inventory(
            &response(
                json!([{
                    "type": "table",
                    "name": "d1_migrations",
                    "tbl_name": "d1_migrations",
                    "sql": "CREATE TABLE \"d1_migrations\"(\n\t\tid         INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tname       TEXT UNIQUE,\n\t\tapplied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL\n)",
                }]),
                json!(true),
            ),
            "d1_migrations",
        )
        .expect("legacy Wrangler spelling remains parseable conflict evidence");
        assert_eq!(
            broader_wrangler_schema.state(),
            D1BootstrapInventoryState::Conflicting,
            "bootstrap recovery accepts only the exact initializer-installed schema"
        );

        let conflicting = parse_d1_bootstrap_inventory(
            &response(
                json!([{
                    "type": "table",
                    "name": "application_rows",
                    "tbl_name": "application_rows",
                    "sql": "CREATE TABLE application_rows(id INTEGER)",
                }]),
                json!(true),
            ),
            "d1_migrations",
        )
        .expect("well-formed conflict evidence");
        assert_eq!(conflicting.state(), D1BootstrapInventoryState::Conflicting);
    }

    #[test]
    fn inventory_rejects_non_primary_and_malformed_rows() {
        let non_primary =
            parse_d1_bootstrap_inventory(&response(json!([]), json!(false)), "d1_migrations")
                .expect_err("replica evidence must fail closed");
        assert_eq!(
            non_primary.structured_content.expect("structured error")["error"]["code"],
            "d1.bootstrap_inventory_not_primary"
        );

        let malformed = parse_d1_bootstrap_inventory(
            &response(
                json!([{"type": "table", "name": "x", "tbl_name": "x"}]),
                json!(true),
            ),
            "d1_migrations",
        )
        .expect_err("partial projection must fail closed");
        assert_eq!(
            malformed.structured_content.expect("structured error")["error"]["code"],
            "d1.bootstrap_inventory_malformed"
        );
    }

    #[test]
    fn initializer_acknowledgement_accepts_zero_row_ddl_but_remains_strict() {
        let acknowledgement = json!([{
            "success": true,
            "errors": [],
            "results": [],
            "meta": {
                "served_by_primary": true,
                "changed_db": true,
                "changes": 0,
                "rows_written": 0,
            },
        }]);
        validate_d1_bootstrap_initializer_write_result(&acknowledgement)
            .expect("DDL acknowledgement permits typed zero row counts");

        let assert_no_retry_cause = |candidate: &Value, expected_classification: &str| {
            let cause = validate_d1_bootstrap_initializer_write_result(candidate)
                .expect_err("malformed initializer acknowledgement must fail closed");
            assert_eq!(
                cause,
                json!({
                    "code": "d1.bootstrap_initializer_result_ambiguous",
                    "classification": expected_classification,
                    "message": cause["message"],
                    "retryable": false,
                    "operator_guidance": "reconciliation_only",
                })
            );
            assert!(
                cause["message"]
                    .as_str()
                    .is_some_and(|message| !message.is_empty())
            );
        };

        let mut unchanged = acknowledgement.clone();
        unchanged[0]["meta"]["changed_db"] = json!(false);
        assert_no_retry_cause(&unchanged, "database_change_not_acknowledged");

        let mut non_primary = acknowledgement.clone();
        non_primary[0]["meta"]["served_by_primary"] = json!(false);
        assert_no_retry_cause(&non_primary, "write_not_served_by_primary");

        let mut malformed_count = acknowledgement.clone();
        malformed_count[0]["meta"]["rows_written"] = json!(-1);
        assert_no_retry_cause(&malformed_count, "missing_or_malformed_write_metadata");

        let mut unexpected_rows = acknowledgement.clone();
        unexpected_rows[0]["results"] = json!([{"unexpected": true}]);
        assert_no_retry_cause(&unexpected_rows, "unexpected_inner_results");

        let mut provider_error = acknowledgement;
        provider_error[0]["errors"] = json!([{
            "code": 9911,
            "message": "provider-private-result-marker",
        }]);
        let cause = validate_d1_bootstrap_initializer_write_result(&provider_error)
            .expect_err("provider error rows must be static ambiguity evidence");
        assert_eq!(cause["classification"], json!("inner_statement_error"));
        assert_eq!(cause["retryable"], json!(false));
        assert_eq!(cause["operator_guidance"], json!("reconciliation_only"));
        assert!(!cause.to_string().contains("provider-private-result-marker"));
        let write = D1MigrationManifestWrite {
            result: Value::Null,
            response_body_sha256:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(), // DevSkim: ignore DS173237 -- synthetic SHA-256 fixture, not a credential
            response_body_size_bytes: 123,
            lifecycle: D1MigrationManifestWriteLifecycle {
                dispatch_stage: "attempted",
                response_stage: "received",
                body_stage: "completely_read",
                http_status: Some(200),
            },
        };
        let nested = bootstrap_initializer_provider_result_cause(&cause, &write);
        assert_eq!(nested["kind"], json!("provider_result"));
        assert_eq!(nested["detail"]["retryable"], json!(false));
        assert_eq!(
            nested["detail"]["operator_guidance"],
            json!("reconciliation_only")
        );
        assert_eq!(
            nested["detail"]["classification"],
            json!("inner_statement_error")
        );
        assert_eq!(
            nested["detail"]["provider_write_lifecycle"],
            json!({
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            })
        );
        assert_eq!(
            nested["detail"]["response_body_sha256"],
            json!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") // DevSkim: ignore DS173237 -- synthetic SHA-256 fixture, not a credential
        );
        assert_eq!(nested["detail"]["response_body_size_bytes"], json!(123));
        assert!(
            !nested
                .to_string()
                .contains("provider-private-result-marker")
        );
    }

    #[test]
    fn plan_digest_binds_every_canonical_target_component_and_initializer() {
        let sql = d1_migrations_table_init_sql("d1_migrations");
        let plan = d1_bootstrap_plan_sha256(
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            "d1_migrations",
            &sql,
        );
        assert!(d1_bootstrap_plan_matches(Some(&plan), &plan));
        assert!(!d1_bootstrap_plan_matches(
            Some(&plan.to_ascii_uppercase()),
            &plan
        ));
        assert_ne!(
            plan,
            d1_bootstrap_plan_sha256(
                "acct-1",
                "223e4567-e89b-42d3-a456-426614174000",
                "d1_migrations",
                &sql
            )
        );
        assert_ne!(
            plan,
            d1_bootstrap_plan_sha256(
                "acct-1",
                "123e4567-e89b-42d3-a456-426614174000",
                "other_ledger",
                &sql
            )
        );
    }
}
