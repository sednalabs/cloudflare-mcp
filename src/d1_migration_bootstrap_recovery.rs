//! Recovery-only authority for an ambiguous migration-ledger bootstrap.
//!
//! This boundary never submits initializer or migration SQL. Read-only
//! reconciliation proves one exact retained bootstrap lease against two stable
//! primary evidence windows. Terminal finalization reproduces that proof,
//! persists one approval-bound local receipt without replacement, re-proves
//! the provider state, and only then retires the retained target lease.

use rmcp::model::CallToolResult;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::cloudflare::client::{
    D1MigrationReconciliationReadLifecycle, d1_migration_reconciliation_only_cause,
};
use crate::d1_migration_bootstrap::{
    D1_BOOTSTRAP_LEASE_FAMILY, D1BootstrapInventoryState, d1_bootstrap_installed_schema_sql,
    d1_bootstrap_inventory_sql, d1_bootstrap_plan_sha256, parse_d1_bootstrap_inventory,
};
use crate::d1_migration_lease::{
    D1RetainedMigrationLease, D1TerminalCustodyNamespace, D1TerminalEvidenceReadback,
    D1TerminalReconciliationReceipt, inspect_retained_d1_migration_lease,
    inspect_terminal_d1_migration_lease,
};
use crate::d1_migration_manifest::{
    D1ManifestLedgerRow, d1_migrations_table_init_sql, parse_d1_migration_ledger,
};
use crate::server::CloudflareMcp;
use crate::tools::{d1_applied_migrations_sql, sha256_bytes_hex, sha256_hex};

pub(crate) const D1_BOOTSTRAP_RECONCILE_OPERATION: &str = "d1_reconcile_bootstrap_migration_ledger";
pub(crate) const D1_BOOTSTRAP_FINALIZE_OPERATION: &str = "d1_finalize_bootstrap_migration_ledger";
pub(crate) const D1_BOOTSTRAP_ABORT_OPERATION: &str = "d1_abort_bootstrap_migration_ledger";
const BOOTSTRAP_EFFECT_ASSERTION_ID: &str = "bootstrap_canonical_empty_ledger_v1";
const BOOTSTRAP_OUTCOME: &str = "full_state_converged";

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1ReconcileBootstrapMigrationLedgerArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub database_id: String,
    #[serde(default)]
    pub migrations_table: Option<String>,
    pub approved_bootstrap_plan_sha256: String,
    pub lease_nonce: String,
    pub lease_payload_sha256: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1FinalizeBootstrapMigrationLedgerArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub database_id: String,
    #[serde(default)]
    pub migrations_table: Option<String>,
    pub approved_bootstrap_plan_sha256: String,
    pub lease_nonce: String,
    pub lease_payload_sha256: String,
    pub expected_reconciliation_plan_sha256: String,
    pub expected_initializer_authority_sha256: String,
    pub expected_query_authority_sha256: String,
    pub expected_canonical_snapshot_sha256: String,
    pub terminal_request_sha256: String,
    pub terminal_attempt_sha256: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub approved_terminal_plan_sha256: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1AbortBootstrapMigrationLedgerArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub database_id: String,
    #[serde(default)]
    pub migrations_table: Option<String>,
    pub approved_bootstrap_plan_sha256: String,
    pub lease_nonce: String,
    pub lease_payload_sha256: String,
    pub terminal_request_sha256: String,
    pub terminal_attempt_sha256: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub approved_terminal_plan_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct BootstrapSnapshot {
    version: u8,
    migrations_table: String,
    inventory_state: &'static str,
    observed_object_count: usize,
    ledger_row_count: usize,
    initializer_sql_sha256: String,
    initializer_sql_size_bytes: usize,
    installed_schema_sha256: String,
}

struct BootstrapWindow {
    snapshot: BootstrapSnapshot,
    snapshot_sha256: String,
    provider_calls: usize,
    lifecycle: Vec<Value>,
}

struct BootstrapWindowFailure {
    result: CallToolResult,
    provider_calls: usize,
    lifecycle: Vec<Value>,
    capability_state: &'static str,
    custody_unverified: bool,
}

struct BootstrapProof {
    lease: D1RetainedMigrationLease,
    reconciliation_plan_sha256: String,
    initializer_authority_sha256: String,
    query_authority_sha256: String,
    canonical_snapshot_sha256: String,
    provider_calls: usize,
    lifecycle: Vec<Value>,
    response_evidence: Vec<Value>,
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn recovery_error(code: &'static str, message: &'static str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": code,
            "message": message,
            "hint": "Keep the exact bootstrap custody evidence. Do not retry the initializer or substitute a migration manifest.",
        },
    }))
}

fn contextualize_failure(
    result: CallToolResult,
    operation: &'static str,
    capability_state: &'static str,
    provider_calls: usize,
    lifecycle: Vec<Value>,
    custody_status: &'static str,
    lease_retained: Value,
    local_namespace_mutations: usize,
) -> CallToolResult {
    let response_evidence = response_evidence_from_lifecycle(&lifecycle);
    let error = result
        .structured_content
        .as_ref()
        .and_then(|content| content.get("error"))
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "code": "d1.bootstrap_recovery_failed",
                "message": "bootstrap recovery failed closed",
                "hint": "Preserve exact retained custody and reconcile the provider evidence.",
            })
        });
    let lease_decision = match lease_retained.as_bool() {
        Some(true) => json!("retain"),
        Some(false) => json!("retired"),
        None => Value::Null,
    };
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": operation,
        "read_only": operation == D1_BOOTSTRAP_RECONCILE_OPERATION,
        "status": "reconciliation_required",
        "outcome": if capability_state == "conflicting" { "conflict" } else { "unknown" },
        "capability_state": capability_state,
        "migration_family": D1_BOOTSTRAP_LEASE_FAMILY,
        "retry_decision": "do_not_retry_initializer",
        "lease_decision": lease_decision,
        "lease_retained": lease_retained,
        "custody_status": custody_status,
        "provider_calls": provider_calls,
        "provider_read_lifecycle": lifecycle,
        "response_evidence": response_evidence,
        "provider_mutations": 0,
        "local_namespace_mutations": local_namespace_mutations,
        "receipt_persisted": Value::Null,
        "error": error,
    }))
}

fn failure_custody(
    lease: &D1RetainedMigrationLease,
    custody_unverified: bool,
) -> (&'static str, Value) {
    if custody_unverified || lease.revalidate().is_err() {
        ("retained_evidence_unverified", Value::Null)
    } else {
        (custody_status(lease), terminal_lease_retained(lease))
    }
}

fn with_receipt_persisted(mut result: CallToolResult, receipt_persisted: Value) -> CallToolResult {
    if let Some(Value::Object(content)) = result.structured_content.as_mut() {
        content.insert("receipt_persisted".to_string(), receipt_persisted);
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn contextualize_post_receipt_failure(
    result: CallToolResult,
    capability_state: &'static str,
    provider_calls: usize,
    lifecycle: Vec<Value>,
    custody_status: &'static str,
    lease_retained: Value,
    local_namespace_mutations: usize,
) -> CallToolResult {
    with_receipt_persisted(
        contextualize_failure(
            result,
            D1_BOOTSTRAP_FINALIZE_OPERATION,
            capability_state,
            provider_calls,
            lifecycle,
            custody_status,
            lease_retained,
            local_namespace_mutations,
        ),
        json!(true),
    )
}

fn contextualize_post_create_receipt_failure(
    result: CallToolResult,
    provider_calls: usize,
    lifecycle: Vec<Value>,
    readback: D1TerminalEvidenceReadback,
    local_namespace_mutations: usize,
) -> CallToolResult {
    let (custody, lease_retained) = terminal_readback_custody_fields(readback);
    with_receipt_persisted(
        contextualize_failure(
            result,
            D1_BOOTSTRAP_FINALIZE_OPERATION,
            "unknown",
            provider_calls,
            lifecycle,
            custody,
            lease_retained,
            local_namespace_mutations,
        ),
        readback
            .receipt_persisted
            .map(Value::Bool)
            .unwrap_or(Value::Null),
    )
}

fn contextualize_abort_post_create_failure(
    result: CallToolResult,
    capability_state: &'static str,
    readback: D1TerminalEvidenceReadback,
    local_namespace_mutations: usize,
) -> CallToolResult {
    let (custody, lease_retained) = terminal_readback_custody_fields(readback);
    with_receipt_persisted(
        contextualize_failure(
            result,
            D1_BOOTSTRAP_ABORT_OPERATION,
            capability_state,
            0,
            Vec::new(),
            custody,
            lease_retained,
            local_namespace_mutations,
        ),
        readback
            .receipt_persisted
            .map(Value::Bool)
            .unwrap_or(Value::Null),
    )
}

fn initializer_authority_sha256(migrations_table: &str) -> String {
    let initializer = d1_migrations_table_init_sql(migrations_table);
    let installed = d1_bootstrap_installed_schema_sql(migrations_table);
    sha256_bytes_hex(
        &serde_json::to_vec(&json!({
            "version": 1,
            "effect_assertion_id": BOOTSTRAP_EFFECT_ASSERTION_ID,
            "migrations_table": migrations_table,
            "initializer_sql_sha256": sha256_hex(&initializer),
            "initializer_sql_size_bytes": initializer.len(),
            "installed_schema_sha256": sha256_hex(&installed),
            "installed_schema_size_bytes": installed.len(),
        }))
        .expect("bootstrap initializer authority serialization is infallible"),
    )
}

fn query_authority_sha256(migrations_table: &str) -> String {
    let inventory_sql = d1_bootstrap_inventory_sql();
    let ledger_sql = d1_applied_migrations_sql(migrations_table);
    sha256_bytes_hex(
        &serde_json::to_vec(&json!({
            "version": 2,
            "inventory_sql_sha256": sha256_hex(inventory_sql),
            "inventory_sql_size_bytes": inventory_sql.len(),
            "ledger_sql_sha256": sha256_hex(&ledger_sql),
            "ledger_sql_size_bytes": ledger_sql.len(),
            "stable_primary_reads_per_query": 2,
            "proof_windows": 2,
            "one_http_attempt_per_read": true,
            "redirects_followed": false,
            "response_body_sha256_required": true,
            "response_body_size_limit_bytes": 16 * 1024 * 1024,
        }))
        .expect("bootstrap query authority serialization is infallible"),
    )
}

fn snapshot_sha256(snapshot: &BootstrapSnapshot) -> String {
    sha256_bytes_hex(
        &serde_json::to_vec(snapshot).expect("bootstrap snapshot serialization is infallible"),
    )
}

struct ExactStableRead<T> {
    value: T,
    provider_calls: usize,
    lifecycle: Vec<Value>,
}

fn attempted_provider_calls(lifecycle: &D1MigrationReconciliationReadLifecycle) -> usize {
    lifecycle.provider_calls()
}

fn exact_read_lifecycle(
    phase: &str,
    query_sha256: &str,
    lifecycle: &D1MigrationReconciliationReadLifecycle,
    response_body_sha256: Option<&str>,
    response_body_size_bytes: Option<usize>,
    parse_state: &'static str,
) -> Value {
    json!({
        "phase": phase,
        "query_sha256": query_sha256,
        "provider_call_attempted": lifecycle.dispatch_stage == "attempted",
        "lifecycle": lifecycle,
        "response": {
            "body_sha256": response_body_sha256,
            "body_size_bytes": response_body_size_bytes,
            "parse_state": parse_state,
        },
    })
}

fn response_evidence_from_lifecycle(lifecycle: &[Value]) -> Vec<Value> {
    lifecycle
        .iter()
        .filter_map(|entry| {
            entry
                .get("response")
                .and_then(|response| {
                    response
                        .get("body_sha256")
                        .and_then(Value::as_str)
                        .map(|_| response)
                })
                .map(|response| {
                    json!({
                        "phase": entry.get("phase").cloned().unwrap_or(Value::Null),
                        "query_sha256": entry
                            .get("query_sha256")
                            .cloned()
                            .unwrap_or(Value::Null),
                        "response": response,
                    })
                })
        })
        .collect()
}

fn reconciliation_lease_fields(namespace: &str) -> (Value, Value) {
    if namespace == "active" {
        (json!("retain_until_terminal_receipt"), json!(true))
    } else {
        (Value::Null, Value::Null)
    }
}

fn exact_read_failure(code: &'static str, message: &'static str, cause: Value) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": code,
            "message": message,
            "hint": "Retain exact bootstrap custody and treat provider evidence as unavailable; never retry the initializer.",
            "cause": cause,
        },
    }))
}

async fn read_exact_inventory_once(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    phase: &str,
) -> Result<
    ExactStableRead<crate::d1_migration_bootstrap::D1BootstrapInventory>,
    BootstrapWindowFailure,
> {
    let sql = d1_bootstrap_inventory_sql();
    let query_sha256 = sha256_hex(sql);
    match server
        .cloudflare
        .query_d1_migration_reconciliation_batch(account_id, database_id, sql)
        .await
    {
        Ok(batch) => {
            let provider_calls = attempted_provider_calls(&batch.lifecycle);
            let lifecycle = exact_read_lifecycle(
                phase,
                &query_sha256,
                &batch.lifecycle,
                Some(&batch.response_body_sha256),
                Some(batch.response_body_size_bytes),
                "decoded",
            );
            parse_d1_bootstrap_inventory(&batch.result, migrations_table)
                .map(|value| ExactStableRead {
                    value,
                    provider_calls,
                    lifecycle: vec![lifecycle.clone()],
                })
                .map_err(|result| BootstrapWindowFailure {
                    result,
                    provider_calls,
                    lifecycle: vec![lifecycle],
                    capability_state: "unknown",
                    custody_unverified: false,
                })
        }
        Err(failure) => {
            let provider_calls = attempted_provider_calls(&failure.lifecycle);
            let lifecycle = exact_read_lifecycle(
                phase,
                &query_sha256,
                &failure.lifecycle,
                failure.response_body_sha256.as_deref(),
                failure.response_body_size_bytes,
                "unavailable",
            );
            Err(BootstrapWindowFailure {
                result: exact_read_failure(
                    "d1.bootstrap_recovery_inventory_unavailable",
                    "the bounded bootstrap inventory response was unavailable or malformed",
                    d1_migration_reconciliation_only_cause(&failure.error),
                ),
                provider_calls,
                lifecycle: vec![lifecycle],
                capability_state: "unknown",
                custody_unverified: false,
            })
        }
    }
}

async fn read_stable_exact_inventory(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    phase: &str,
) -> Result<
    ExactStableRead<crate::d1_migration_bootstrap::D1BootstrapInventory>,
    BootstrapWindowFailure,
> {
    let first = read_exact_inventory_once(
        server,
        account_id,
        database_id,
        migrations_table,
        &format!("{phase}.inventory.first"),
    )
    .await?;
    let second = read_exact_inventory_once(
        server,
        account_id,
        database_id,
        migrations_table,
        &format!("{phase}.inventory.second"),
    )
    .await
    .map_err(|mut failure| {
        failure.provider_calls += first.provider_calls;
        let mut lifecycle = first.lifecycle.clone();
        lifecycle.extend(failure.lifecycle);
        failure.lifecycle = lifecycle;
        failure
    })?;
    let provider_calls = first.provider_calls + second.provider_calls;
    let mut lifecycle = first.lifecycle;
    lifecycle.extend(second.lifecycle);
    if first.value != second.value {
        return Err(BootstrapWindowFailure {
            result: recovery_error(
                "d1.bootstrap_recovery_inventory_unstable",
                "two exact one-attempt primary inventory reads disagreed",
            ),
            provider_calls,
            lifecycle,
            capability_state: "unknown",
            custody_unverified: false,
        });
    }
    Ok(ExactStableRead {
        value: first.value,
        provider_calls,
        lifecycle,
    })
}

async fn read_exact_ledger_once(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    phase: &str,
) -> Result<ExactStableRead<Vec<D1ManifestLedgerRow>>, BootstrapWindowFailure> {
    let sql = d1_applied_migrations_sql(migrations_table);
    let query_sha256 = sha256_hex(&sql);
    match server
        .cloudflare
        .query_d1_migration_reconciliation_batch(account_id, database_id, &sql)
        .await
    {
        Ok(batch) => {
            let provider_calls = attempted_provider_calls(&batch.lifecycle);
            let lifecycle = exact_read_lifecycle(
                phase,
                &query_sha256,
                &batch.lifecycle,
                Some(&batch.response_body_sha256),
                Some(batch.response_body_size_bytes),
                "decoded",
            );
            parse_d1_migration_ledger(&batch.result)
                .map(|value| ExactStableRead {
                    value,
                    provider_calls,
                    lifecycle: vec![lifecycle.clone()],
                })
                .map_err(|result| BootstrapWindowFailure {
                    result,
                    provider_calls,
                    lifecycle: vec![lifecycle],
                    capability_state: "unknown",
                    custody_unverified: false,
                })
        }
        Err(failure) => {
            let provider_calls = attempted_provider_calls(&failure.lifecycle);
            let lifecycle = exact_read_lifecycle(
                phase,
                &query_sha256,
                &failure.lifecycle,
                failure.response_body_sha256.as_deref(),
                failure.response_body_size_bytes,
                "unavailable",
            );
            Err(BootstrapWindowFailure {
                result: exact_read_failure(
                    "d1.bootstrap_recovery_ledger_unavailable",
                    "the bounded bootstrap ledger response was unavailable or malformed",
                    d1_migration_reconciliation_only_cause(&failure.error),
                ),
                provider_calls,
                lifecycle: vec![lifecycle],
                capability_state: "unknown",
                custody_unverified: false,
            })
        }
    }
}

async fn read_stable_exact_ledger(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    phase: &str,
) -> Result<ExactStableRead<Vec<D1ManifestLedgerRow>>, BootstrapWindowFailure> {
    let first = read_exact_ledger_once(
        server,
        account_id,
        database_id,
        migrations_table,
        &format!("{phase}.ledger.first"),
    )
    .await?;
    let second = read_exact_ledger_once(
        server,
        account_id,
        database_id,
        migrations_table,
        &format!("{phase}.ledger.second"),
    )
    .await
    .map_err(|mut failure| {
        failure.provider_calls += first.provider_calls;
        let mut lifecycle = first.lifecycle.clone();
        lifecycle.extend(failure.lifecycle);
        failure.lifecycle = lifecycle;
        failure
    })?;
    let provider_calls = first.provider_calls + second.provider_calls;
    let mut lifecycle = first.lifecycle;
    lifecycle.extend(second.lifecycle);
    if first.value != second.value {
        return Err(BootstrapWindowFailure {
            result: recovery_error(
                "d1.bootstrap_recovery_ledger_unstable",
                "two exact one-attempt primary ledger reads disagreed",
            ),
            provider_calls,
            lifecycle,
            capability_state: "unknown",
            custody_unverified: false,
        });
    }
    Ok(ExactStableRead {
        value: first.value,
        provider_calls,
        lifecycle,
    })
}

async fn read_bootstrap_window(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    phase: &'static str,
) -> Result<BootstrapWindow, BootstrapWindowFailure> {
    let inventory_read =
        read_stable_exact_inventory(server, account_id, database_id, migrations_table, phase)
            .await?;
    let inventory = inventory_read.value;
    let inventory_calls = inventory_read.provider_calls;
    let mut lifecycle = inventory_read.lifecycle;
    match inventory.state() {
        D1BootstrapInventoryState::Empty => {
            return Err(BootstrapWindowFailure {
                result: recovery_error(
                    "d1.bootstrap_recovery_ledger_absent",
                    "the exact canonical bootstrap initializer product is absent",
                ),
                provider_calls: inventory_calls,
                lifecycle,
                capability_state: "conflicting",
                custody_unverified: false,
            });
        }
        D1BootstrapInventoryState::Conflicting => {
            return Err(BootstrapWindowFailure {
                result: recovery_error(
                    "d1.bootstrap_recovery_schema_conflict",
                    "provider schema does not equal the exact canonical bootstrap initializer product",
                ),
                provider_calls: inventory_calls,
                lifecycle,
                capability_state: "conflicting",
                custody_unverified: false,
            });
        }
        D1BootstrapInventoryState::CanonicalLedger => {}
    }
    let ledger_read =
        read_stable_exact_ledger(server, account_id, database_id, migrations_table, phase)
            .await
            .map_err(|mut failure| {
                failure.provider_calls += inventory_calls;
                let mut combined = lifecycle.clone();
                combined.extend(failure.lifecycle);
                failure.lifecycle = combined;
                failure
            })?;
    let ledger = ledger_read.value;
    let ledger_calls = ledger_read.provider_calls;
    lifecycle.extend(ledger_read.lifecycle);
    if !ledger.is_empty() {
        return Err(BootstrapWindowFailure {
            result: recovery_error(
                "d1.bootstrap_recovery_ledger_not_empty",
                "the exact bootstrap ledger exists but is not canonically empty",
            ),
            provider_calls: inventory_calls + ledger_calls,
            lifecycle,
            capability_state: "conflicting",
            custody_unverified: false,
        });
    }
    let initializer = d1_migrations_table_init_sql(migrations_table);
    let installed = d1_bootstrap_installed_schema_sql(migrations_table);
    let snapshot = BootstrapSnapshot {
        version: 1,
        migrations_table: migrations_table.to_string(),
        inventory_state: "canonical_ledger_only",
        observed_object_count: 1,
        ledger_row_count: ledger.len(),
        initializer_sql_sha256: sha256_hex(&initializer),
        initializer_sql_size_bytes: initializer.len(),
        installed_schema_sha256: sha256_hex(&installed),
    };
    Ok(BootstrapWindow {
        snapshot_sha256: snapshot_sha256(&snapshot),
        snapshot,
        provider_calls: inventory_calls + ledger_calls,
        lifecycle,
    })
}

#[allow(clippy::too_many_arguments)]
fn reconciliation_plan_sha256(
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    approved_bootstrap_plan_sha256: &str,
    lease: &D1RetainedMigrationLease,
    initializer_authority_sha256: &str,
    query_authority_sha256: &str,
    canonical_snapshot_sha256: &str,
) -> String {
    sha256_bytes_hex(
        &serde_json::to_vec(&json!({
            "version": 1,
            "operation": D1_BOOTSTRAP_RECONCILE_OPERATION,
            "target_key_sha256": sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes()),
            "migration_family": D1_BOOTSTRAP_LEASE_FAMILY,
            "migrations_table": migrations_table,
            "approved_bootstrap_plan_sha256": approved_bootstrap_plan_sha256,
            "lease_nonce": lease.identity.nonce,
            "lease_payload_sha256": lease.identity.payload_sha256,
            "initializer_authority_sha256": initializer_authority_sha256,
            "query_authority_sha256": query_authority_sha256,
            "canonical_snapshot_sha256": canonical_snapshot_sha256,
            "outcome": "canonical_empty_ledger",
            "retry_decision": "do_not_retry_initializer",
            "lease_decision": "retain_until_terminal_receipt",
            "provider_mutations": 0,
        }))
        .expect("bootstrap reconciliation plan serialization is infallible"),
    )
}

#[allow(clippy::too_many_arguments)]
async fn prepare_bootstrap_reconciliation(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    approved_bootstrap_plan_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
) -> Result<BootstrapProof, CallToolResult> {
    let initializer = d1_migrations_table_init_sql(migrations_table);
    let computed_bootstrap_plan =
        d1_bootstrap_plan_sha256(account_id, database_id, migrations_table, &initializer);
    if !valid_lower_sha256(approved_bootstrap_plan_sha256)
        || approved_bootstrap_plan_sha256 != computed_bootstrap_plan
    {
        return Err(contextualize_failure(
            recovery_error(
                "d1.bootstrap_recovery_plan_mismatch",
                "the supplied bootstrap plan does not reproduce the exact target, table, and initializer authority",
            ),
            D1_BOOTSTRAP_RECONCILE_OPERATION,
            "contradictory",
            0,
            Vec::new(),
            "not_inspected",
            Value::Null,
            0,
        ));
    }
    let lease = inspect_retained_d1_migration_lease(
        account_id,
        database_id,
        D1_BOOTSTRAP_LEASE_FAMILY,
        approved_bootstrap_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
    )
    .map_err(|result| {
        contextualize_failure(
            result,
            D1_BOOTSTRAP_RECONCILE_OPERATION,
            "contradictory",
            0,
            Vec::new(),
            "inspection_failed",
            Value::Null,
            0,
        )
    })?;
    let before = read_bootstrap_window(server, account_id, database_id, migrations_table, "before")
        .await
        .map_err(|failure| {
            let (custody, lease_retained) = failure_custody(&lease, failure.custody_unverified);
            contextualize_failure(
                failure.result,
                D1_BOOTSTRAP_RECONCILE_OPERATION,
                failure.capability_state,
                failure.provider_calls,
                failure.lifecycle,
                custody,
                lease_retained,
                0,
            )
        })?;
    lease.revalidate().map_err(|result| {
        contextualize_failure(
            result,
            D1_BOOTSTRAP_RECONCILE_OPERATION,
            "unknown",
            before.provider_calls,
            before.lifecycle.clone(),
            "retained_evidence_unverified",
            Value::Null,
            0,
        )
    })?;
    let after = read_bootstrap_window(server, account_id, database_id, migrations_table, "after")
        .await
        .map_err(|failure| {
            let mut lifecycle = before.lifecycle.clone();
            lifecycle.extend(failure.lifecycle);
            let (custody, lease_retained) = failure_custody(&lease, failure.custody_unverified);
            contextualize_failure(
                failure.result,
                D1_BOOTSTRAP_RECONCILE_OPERATION,
                failure.capability_state,
                before.provider_calls + failure.provider_calls,
                lifecycle,
                custody,
                lease_retained,
                0,
            )
        })?;
    let mut lifecycle = before.lifecycle;
    lifecycle.extend(after.lifecycle);
    let provider_calls = before.provider_calls + after.provider_calls;
    if before.snapshot != after.snapshot || before.snapshot_sha256 != after.snapshot_sha256 {
        let (custody, lease_retained) = failure_custody(&lease, false);
        return Err(contextualize_failure(
            recovery_error(
                "d1.bootstrap_recovery_state_unstable",
                "the canonical provider snapshot changed between stable primary proof windows",
            ),
            D1_BOOTSTRAP_RECONCILE_OPERATION,
            "unknown",
            provider_calls,
            lifecycle,
            custody,
            lease_retained,
            0,
        ));
    }
    lease.revalidate().map_err(|result| {
        contextualize_failure(
            result,
            D1_BOOTSTRAP_RECONCILE_OPERATION,
            "unknown",
            provider_calls,
            lifecycle.clone(),
            "retained_evidence_unverified",
            Value::Null,
            0,
        )
    })?;
    let initializer_authority_sha256 = initializer_authority_sha256(migrations_table);
    let query_authority_sha256 = query_authority_sha256(migrations_table);
    let reconciliation_plan_sha256 = reconciliation_plan_sha256(
        account_id,
        database_id,
        migrations_table,
        approved_bootstrap_plan_sha256,
        &lease,
        &initializer_authority_sha256,
        &query_authority_sha256,
        &before.snapshot_sha256,
    );
    let mut response_evidence = response_evidence_from_lifecycle(&lifecycle);
    response_evidence.push(json!({
        "before_snapshot_sha256": before.snapshot_sha256,
        "after_snapshot_sha256": after.snapshot_sha256,
        "stable_primary_before_after_match": true,
        "exact_initializer_schema": true,
        "ledger_row_count": 0,
    }));
    Ok(BootstrapProof {
        lease,
        reconciliation_plan_sha256,
        initializer_authority_sha256,
        query_authority_sha256,
        canonical_snapshot_sha256: before.snapshot_sha256,
        provider_calls,
        lifecycle,
        response_evidence,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn reconcile_bootstrap_migration_ledger(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    approved_bootstrap_plan_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
) -> CallToolResult {
    let proof = match prepare_bootstrap_reconciliation(
        server,
        account_id,
        database_id,
        migrations_table,
        approved_bootstrap_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
    )
    .await
    {
        Ok(proof) => proof,
        Err(result) => return result,
    };
    let (lease_decision, lease_retained) =
        reconciliation_lease_fields(&proof.lease.identity.namespace);
    CallToolResult::structured(json!({
        "ok": true,
        "operation": D1_BOOTSTRAP_RECONCILE_OPERATION,
        "read_only": true,
        "status": "bootstrap_reconciled",
        "outcome": "canonical_empty_ledger",
        "capability_state": "terminal_proof_ready",
        "migration_family": D1_BOOTSTRAP_LEASE_FAMILY,
        "migrations_table": migrations_table,
        "approved_bootstrap_plan_sha256": approved_bootstrap_plan_sha256,
        "reconciliation_plan_sha256": proof.reconciliation_plan_sha256,
        "initializer_authority_sha256": proof.initializer_authority_sha256,
        "query_authority_sha256": proof.query_authority_sha256,
        "canonical_snapshot_sha256": proof.canonical_snapshot_sha256,
        "effect_attribution": "unknown",
        "retry_decision": "do_not_retry_initializer",
        "lease_decision": lease_decision,
        "lease_retained": lease_retained,
        "custody_status": custody_status(&proof.lease),
        "provider_calls": proof.provider_calls,
        "provider_read_lifecycle": proof.lifecycle,
        "response_evidence": proof.response_evidence,
        "provider_mutations": 0,
        "local_namespace_mutations": 0,
    }))
}

#[allow(clippy::too_many_arguments)]
fn terminal_plan_sha256(
    target_key_sha256: &str,
    migrations_table: &str,
    approved_bootstrap_plan_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
    reconciliation_plan_sha256: &str,
    initializer_authority_sha256: &str,
    query_authority_sha256: &str,
    canonical_snapshot_sha256: &str,
    terminal_request_sha256: &str,
    terminal_attempt_sha256: &str,
) -> String {
    sha256_bytes_hex(
        &serde_json::to_vec(&json!({
            "version": 1,
            "operation": D1_BOOTSTRAP_FINALIZE_OPERATION,
            "target_key_sha256": target_key_sha256,
            "migration_family": D1_BOOTSTRAP_LEASE_FAMILY,
            "migrations_table": migrations_table,
            "approved_bootstrap_plan_sha256": approved_bootstrap_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "reconciliation_plan_sha256": reconciliation_plan_sha256,
            "initializer_authority_sha256": initializer_authority_sha256,
            "query_authority_sha256": query_authority_sha256,
            "canonical_snapshot_sha256": canonical_snapshot_sha256,
            "terminal_request_sha256": terminal_request_sha256,
            "terminal_attempt_sha256": terminal_attempt_sha256,
            "outcome": "canonical_empty_ledger",
            "effect": "persist_exact_terminal_receipt_then_retire_bootstrap_custody",
            "provider_mutations": 0,
        }))
        .expect("bootstrap terminal plan serialization is infallible"),
    )
}

fn custody_status(lease: &D1RetainedMigrationLease) -> &'static str {
    match lease.identity.namespace.as_str() {
        "active" => "retained_evidence_verified",
        "retiring" => "retiring_evidence_verified",
        "retired" => "retired_evidence_verified",
        _ => "retained_evidence_unverified",
    }
}

fn terminal_lease_retained(lease: &D1RetainedMigrationLease) -> Value {
    match lease.identity.namespace.as_str() {
        "active" => json!(true),
        "retired" => json!(false),
        _ => Value::Null,
    }
}

fn terminal_readback_custody_fields(readback: D1TerminalEvidenceReadback) -> (&'static str, Value) {
    match readback.custody {
        D1TerminalCustodyNamespace::Active => ("retained_evidence_verified", json!(true)),
        D1TerminalCustodyNamespace::Retiring => ("retiring_evidence_verified", Value::Null),
        D1TerminalCustodyNamespace::Retired => ("retired_evidence_verified", json!(false)),
        D1TerminalCustodyNamespace::Unverified => ("retained_evidence_unverified", Value::Null),
    }
}

fn terminal_receipt(
    target_key_sha256: String,
    approved_bootstrap_plan_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
    expected_reconciliation_plan_sha256: &str,
    expected_initializer_authority_sha256: &str,
    expected_query_authority_sha256: &str,
    expected_canonical_snapshot_sha256: &str,
    terminal_request_sha256: &str,
    terminal_attempt_sha256: &str,
    terminal_plan_sha256: String,
) -> D1TerminalReconciliationReceipt {
    D1TerminalReconciliationReceipt {
        version: 2,
        operation: D1_BOOTSTRAP_FINALIZE_OPERATION.to_string(),
        target_key_sha256,
        lease_nonce: lease_nonce.to_string(),
        lease_payload_sha256: lease_payload_sha256.to_string(),
        approved_apply_plan_sha256: approved_bootstrap_plan_sha256.to_string(),
        effect_assertion_id: BOOTSTRAP_EFFECT_ASSERTION_ID.to_string(),
        reconciliation_plan_sha256: expected_reconciliation_plan_sha256.to_string(),
        expectation_proof_sha256: expected_initializer_authority_sha256.to_string(),
        query_sha256: expected_query_authority_sha256.to_string(),
        canonical_snapshot_sha256: expected_canonical_snapshot_sha256.to_string(),
        terminal_request_sha256: terminal_request_sha256.to_string(),
        terminal_attempt_sha256: terminal_attempt_sha256.to_string(),
        terminal_plan_sha256,
        outcome: BOOTSTRAP_OUTCOME.to_string(),
        original_prefix_length: 0,
        current_prefix_length: 1,
    }
}

fn exact_expected_proof(
    proof: &BootstrapProof,
    expected_reconciliation_plan_sha256: &str,
    expected_initializer_authority_sha256: &str,
    expected_query_authority_sha256: &str,
    expected_canonical_snapshot_sha256: &str,
) -> bool {
    proof.reconciliation_plan_sha256 == expected_reconciliation_plan_sha256
        && proof.initializer_authority_sha256 == expected_initializer_authority_sha256
        && proof.query_authority_sha256 == expected_query_authority_sha256
        && proof.canonical_snapshot_sha256 == expected_canonical_snapshot_sha256
}

async fn refresh_exact_snapshot(
    server: &CloudflareMcp,
    proof: &D1RetainedMigrationLease,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    phase: &'static str,
    expected_snapshot_sha256: &str,
) -> Result<BootstrapWindow, BootstrapWindowFailure> {
    proof
        .revalidate()
        .map_err(|result| BootstrapWindowFailure {
            result,
            provider_calls: 0,
            lifecycle: Vec::new(),
            capability_state: "unknown",
            custody_unverified: true,
        })?;
    let window =
        read_bootstrap_window(server, account_id, database_id, migrations_table, phase).await?;
    if window.snapshot_sha256 != expected_snapshot_sha256 {
        return Err(BootstrapWindowFailure {
            result: recovery_error(
                "d1.bootstrap_terminal_snapshot_mismatch",
                "fresh provider state does not reproduce the approved canonical empty-ledger snapshot",
            ),
            provider_calls: window.provider_calls,
            lifecycle: window.lifecycle,
            capability_state: "conflicting",
            custody_unverified: false,
        });
    }
    proof
        .revalidate()
        .map_err(|result| BootstrapWindowFailure {
            result,
            provider_calls: window.provider_calls,
            lifecycle: window.lifecycle.clone(),
            capability_state: "unknown",
            custody_unverified: true,
        })?;
    Ok(window)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn finalize_bootstrap_migration_ledger(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    approved_bootstrap_plan_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
    expected_reconciliation_plan_sha256: &str,
    expected_initializer_authority_sha256: &str,
    expected_query_authority_sha256: &str,
    expected_canonical_snapshot_sha256: &str,
    terminal_request_sha256: &str,
    terminal_attempt_sha256: &str,
    dry_run: bool,
    approved_terminal_plan_sha256: Option<&str>,
) -> CallToolResult {
    let required_hashes = [
        approved_bootstrap_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
        expected_reconciliation_plan_sha256,
        expected_initializer_authority_sha256,
        expected_query_authority_sha256,
        expected_canonical_snapshot_sha256,
        terminal_request_sha256,
        terminal_attempt_sha256,
    ];
    if required_hashes
        .into_iter()
        .any(|value| !valid_lower_sha256(value))
        || terminal_request_sha256 == terminal_attempt_sha256
        || (!dry_run
            && approved_terminal_plan_sha256.is_none_or(|value| !valid_lower_sha256(value)))
    {
        return contextualize_failure(
            recovery_error(
                "d1.bootstrap_terminal_request_invalid",
                "terminal bootstrap recovery requires canonical distinct request and attempt digests plus exact approved evidence pins",
            ),
            D1_BOOTSTRAP_FINALIZE_OPERATION,
            "contradictory",
            0,
            Vec::new(),
            "not_inspected",
            Value::Null,
            0,
        );
    }
    let target_key_sha256 = sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes());
    let initializer = d1_migrations_table_init_sql(migrations_table);
    let computed_bootstrap_plan =
        d1_bootstrap_plan_sha256(account_id, database_id, migrations_table, &initializer);
    let computed_initializer_authority = initializer_authority_sha256(migrations_table);
    let computed_query_authority = query_authority_sha256(migrations_table);
    if approved_bootstrap_plan_sha256 != computed_bootstrap_plan
        || expected_initializer_authority_sha256 != computed_initializer_authority
        || expected_query_authority_sha256 != computed_query_authority
    {
        return contextualize_failure(
            recovery_error(
                "d1.bootstrap_terminal_static_authority_mismatch",
                "terminal bootstrap inputs do not reproduce the exact target, table, initializer, and fixed-query authority",
            ),
            D1_BOOTSTRAP_FINALIZE_OPERATION,
            "contradictory",
            0,
            Vec::new(),
            "not_inspected",
            Value::Null,
            0,
        );
    }
    let terminal_plan_sha256 = terminal_plan_sha256(
        &target_key_sha256,
        migrations_table,
        approved_bootstrap_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
        expected_reconciliation_plan_sha256,
        expected_initializer_authority_sha256,
        expected_query_authority_sha256,
        expected_canonical_snapshot_sha256,
        terminal_request_sha256,
        terminal_attempt_sha256,
    );
    if !dry_run && approved_terminal_plan_sha256 != Some(terminal_plan_sha256.as_str()) {
        return contextualize_failure(
            recovery_error(
                "d1.bootstrap_terminal_plan_mismatch",
                "approved_terminal_plan_sha256 does not match this exact terminal recovery plan",
            ),
            D1_BOOTSTRAP_FINALIZE_OPERATION,
            "contradictory",
            0,
            Vec::new(),
            "not_inspected",
            Value::Null,
            0,
        );
    }
    let receipt = terminal_receipt(
        target_key_sha256,
        approved_bootstrap_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
        expected_reconciliation_plan_sha256,
        expected_initializer_authority_sha256,
        expected_query_authority_sha256,
        expected_canonical_snapshot_sha256,
        terminal_request_sha256,
        terminal_attempt_sha256,
        terminal_plan_sha256.clone(),
    );
    let initial_lease = match inspect_terminal_d1_migration_lease(
        account_id,
        database_id,
        D1_BOOTSTRAP_LEASE_FAMILY,
        approved_bootstrap_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
    ) {
        Ok(lease) => lease,
        Err(result) => {
            return contextualize_failure(
                result,
                D1_BOOTSTRAP_FINALIZE_OPERATION,
                "contradictory",
                0,
                Vec::new(),
                "inspection_failed",
                Value::Null,
                0,
            );
        }
    };
    let initial_receipt = match initial_lease.terminal_receipt_state(&receipt) {
        Ok(receipt) => receipt,
        Err(result) => {
            return contextualize_failure(
                result,
                D1_BOOTSTRAP_FINALIZE_OPERATION,
                "contradictory",
                0,
                Vec::new(),
                custody_status(&initial_lease),
                terminal_lease_retained(&initial_lease),
                0,
            );
        }
    };
    let recomputed_reconciliation_plan = reconciliation_plan_sha256(
        account_id,
        database_id,
        migrations_table,
        approved_bootstrap_plan_sha256,
        &initial_lease,
        expected_initializer_authority_sha256,
        expected_query_authority_sha256,
        expected_canonical_snapshot_sha256,
    );
    if recomputed_reconciliation_plan != expected_reconciliation_plan_sha256 {
        return contextualize_failure(
            recovery_error(
                "d1.bootstrap_terminal_reconciliation_plan_mismatch",
                "the supplied terminal evidence does not reproduce the exact retained bootstrap reconciliation plan",
            ),
            D1_BOOTSTRAP_FINALIZE_OPERATION,
            "contradictory",
            0,
            Vec::new(),
            custody_status(&initial_lease),
            terminal_lease_retained(&initial_lease),
            0,
        );
    }
    if initial_lease.is_retired() {
        return match initial_receipt {
            Some(evidence) => CallToolResult::structured(json!({
                "ok": true,
                "operation": D1_BOOTSTRAP_FINALIZE_OPERATION,
                "dry_run": dry_run,
                "status": "bootstrap_terminal_already_complete",
                "replayed": true,
                "terminal_plan_sha256": terminal_plan_sha256,
                "terminal_receipt_sha256": evidence.payload_sha256,
                "migration_family": D1_BOOTSTRAP_LEASE_FAMILY,
                "retry_decision": "do_not_retry_initializer",
                "lease_decision": "retired",
                "lease_retained": false,
                "custody_status": "retired_evidence_verified",
                "provider_calls": 0,
                "provider_read_lifecycle": [],
                "response_evidence": [],
                "provider_mutations": 0,
                "local_namespace_mutations": 0,
            })),
            None => contextualize_failure(
                recovery_error(
                    "d1.bootstrap_terminal_receipt_absent",
                    "retired bootstrap custody exists without its exact terminal receipt",
                ),
                D1_BOOTSTRAP_FINALIZE_OPERATION,
                "contradictory",
                0,
                Vec::new(),
                "retired_evidence_verified",
                json!(false),
                0,
            ),
        };
    }
    if initial_lease.identity.namespace == "retiring" && initial_receipt.is_none() {
        return contextualize_failure(
            recovery_error(
                "d1.bootstrap_terminal_receipt_absent",
                "bootstrap custody entered retiring state without its exact terminal receipt",
            ),
            D1_BOOTSTRAP_FINALIZE_OPERATION,
            "contradictory",
            0,
            Vec::new(),
            "retiring_evidence_verified",
            Value::Null,
            0,
        );
    }
    drop(initial_lease);

    let mut proof = match prepare_bootstrap_reconciliation(
        server,
        account_id,
        database_id,
        migrations_table,
        approved_bootstrap_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
    )
    .await
    {
        Ok(proof) => proof,
        Err(result) => {
            let content = result.structured_content.as_ref();
            let zero_provider_calls = content
                .and_then(|value| value.get("provider_calls"))
                .and_then(Value::as_u64)
                == Some(0);
            if zero_provider_calls
                && let Ok(completed) = inspect_terminal_d1_migration_lease(
                    account_id,
                    database_id,
                    D1_BOOTSTRAP_LEASE_FAMILY,
                    approved_bootstrap_plan_sha256,
                    lease_nonce,
                    lease_payload_sha256,
                )
                && completed.is_retired()
            {
                return match completed.terminal_receipt_state(&receipt) {
                    Ok(Some(evidence)) => CallToolResult::structured(json!({
                        "ok": true,
                        "operation": D1_BOOTSTRAP_FINALIZE_OPERATION,
                        "dry_run": dry_run,
                        "status": "bootstrap_terminal_already_complete",
                        "replayed": true,
                        "terminal_plan_sha256": terminal_plan_sha256,
                        "terminal_receipt_sha256": evidence.payload_sha256,
                        "migration_family": D1_BOOTSTRAP_LEASE_FAMILY,
                        "retry_decision": "do_not_retry_initializer",
                        "lease_decision": "retired",
                        "lease_retained": false,
                        "custody_status": "retired_evidence_verified",
                        "provider_calls": 0,
                        "provider_read_lifecycle": [],
                        "response_evidence": [],
                        "provider_mutations": 0,
                        "local_namespace_mutations": 0,
                    })),
                    Ok(None) => contextualize_failure(
                        recovery_error(
                            "d1.bootstrap_terminal_receipt_absent",
                            "concurrent bootstrap retirement completed without its exact terminal receipt",
                        ),
                        D1_BOOTSTRAP_FINALIZE_OPERATION,
                        "contradictory",
                        0,
                        Vec::new(),
                        "retired_evidence_verified",
                        json!(false),
                        0,
                    ),
                    Err(receipt_error) => contextualize_failure(
                        receipt_error,
                        D1_BOOTSTRAP_FINALIZE_OPERATION,
                        "contradictory",
                        0,
                        Vec::new(),
                        "retired_evidence_verified",
                        json!(false),
                        0,
                    ),
                };
            }
            let capability_state = match content
                .and_then(|value| value.get("capability_state"))
                .and_then(Value::as_str)
            {
                Some("conflicting") => "conflicting",
                Some("contradictory") => "contradictory",
                _ => "unknown",
            };
            let custody = match content
                .and_then(|value| value.get("custody_status"))
                .and_then(Value::as_str)
            {
                Some("retained_evidence_verified") => "retained_evidence_verified",
                Some("retiring_evidence_verified") => "retiring_evidence_verified",
                Some("inspection_failed") => "inspection_failed",
                Some("not_inspected") => "not_inspected",
                _ => "retained_evidence_unverified",
            };
            let provider_calls = content
                .and_then(|value| value.get("provider_calls"))
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            let lifecycle = content
                .and_then(|value| value.get("provider_read_lifecycle"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let lease_retained = content
                .and_then(|value| value.get("lease_retained"))
                .cloned()
                .unwrap_or(Value::Null);
            return contextualize_failure(
                result,
                D1_BOOTSTRAP_FINALIZE_OPERATION,
                capability_state,
                provider_calls,
                lifecycle,
                custody,
                lease_retained,
                0,
            );
        }
    };
    if !exact_expected_proof(
        &proof,
        expected_reconciliation_plan_sha256,
        expected_initializer_authority_sha256,
        expected_query_authority_sha256,
        expected_canonical_snapshot_sha256,
    ) {
        return contextualize_failure(
            recovery_error(
                "d1.bootstrap_terminal_approved_evidence_mismatch",
                "fresh bootstrap proof does not reproduce every approved authority and snapshot pin",
            ),
            D1_BOOTSTRAP_FINALIZE_OPERATION,
            "contradictory",
            proof.provider_calls,
            proof.lifecycle,
            custody_status(&proof.lease),
            terminal_lease_retained(&proof.lease),
            0,
        );
    }
    if dry_run {
        return CallToolResult::structured(json!({
            "ok": true,
            "operation": D1_BOOTSTRAP_FINALIZE_OPERATION,
            "dry_run": true,
            "status": "bootstrap_terminal_plan_ready",
            "terminal_plan_sha256": terminal_plan_sha256,
            "approved_evidence": {
                "reconciliation_plan_sha256": expected_reconciliation_plan_sha256,
                "initializer_authority_sha256": expected_initializer_authority_sha256,
                "query_authority_sha256": expected_query_authority_sha256,
                "canonical_snapshot_sha256": expected_canonical_snapshot_sha256,
                "terminal_request_sha256": terminal_request_sha256,
                "terminal_attempt_sha256": terminal_attempt_sha256,
            },
            "migration_family": D1_BOOTSTRAP_LEASE_FAMILY,
            "retry_decision": "do_not_retry_initializer",
            "lease_decision": if proof.lease.identity.namespace == "active" { json!("retain_until_approved_terminal_call") } else { Value::Null },
            "lease_retained": terminal_lease_retained(&proof.lease),
            "custody_status": custody_status(&proof.lease),
            "provider_calls": proof.provider_calls,
            "provider_read_lifecycle": proof.lifecycle,
            "response_evidence": proof.response_evidence,
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
        }));
    }

    let mut provider_calls = proof.provider_calls;
    let mut lifecycle = proof.lifecycle;
    let mut response_evidence = proof.response_evidence;
    let before_receipt = match refresh_exact_snapshot(
        server,
        &proof.lease,
        account_id,
        database_id,
        migrations_table,
        "before_terminal_receipt",
        expected_canonical_snapshot_sha256,
    )
    .await
    {
        Ok(window) => window,
        Err(failure) => {
            lifecycle.extend(failure.lifecycle);
            let (custody, lease_retained) =
                failure_custody(&proof.lease, failure.custody_unverified);
            return with_receipt_persisted(
                contextualize_failure(
                    failure.result,
                    D1_BOOTSTRAP_FINALIZE_OPERATION,
                    failure.capability_state,
                    provider_calls + failure.provider_calls,
                    lifecycle,
                    custody,
                    lease_retained,
                    0,
                ),
                json!(false),
            );
        }
    };
    provider_calls += before_receipt.provider_calls;
    response_evidence.extend(response_evidence_from_lifecycle(&before_receipt.lifecycle));
    lifecycle.extend(before_receipt.lifecycle);
    response_evidence.push(json!({
        "phase": "before_terminal_receipt",
        "canonical_snapshot_sha256": before_receipt.snapshot_sha256,
        "matches_approved_snapshot": true,
    }));
    let (receipt_evidence, receipt_created) = match proof.lease.persist_terminal_receipt(&receipt) {
        Ok(receipt) => receipt,
        Err(failure) => {
            if failure.local_namespace_mutations == 0 {
                return contextualize_failure(
                    failure.result,
                    D1_BOOTSTRAP_FINALIZE_OPERATION,
                    "unknown",
                    provider_calls,
                    lifecycle,
                    custody_status(&proof.lease),
                    terminal_lease_retained(&proof.lease),
                    0,
                );
            }
            let readback = proof.lease.terminal_evidence_readback(&receipt, None);
            return contextualize_post_create_receipt_failure(
                failure.result,
                provider_calls,
                lifecycle,
                readback,
                failure.local_namespace_mutations,
            );
        }
    };
    let local_receipt_mutations = usize::from(receipt_created);
    let before_retirement = match refresh_exact_snapshot(
        server,
        &proof.lease,
        account_id,
        database_id,
        migrations_table,
        "before_lease_retirement",
        expected_canonical_snapshot_sha256,
    )
    .await
    {
        Ok(window) => window,
        Err(failure) => {
            lifecycle.extend(failure.lifecycle);
            let (custody, lease_retained) =
                failure_custody(&proof.lease, failure.custody_unverified);
            return contextualize_post_receipt_failure(
                failure.result,
                failure.capability_state,
                provider_calls + failure.provider_calls,
                lifecycle,
                custody,
                lease_retained,
                local_receipt_mutations,
            );
        }
    };
    provider_calls += before_retirement.provider_calls;
    response_evidence.extend(response_evidence_from_lifecycle(
        &before_retirement.lifecycle,
    ));
    lifecycle.extend(before_retirement.lifecycle);
    response_evidence.push(json!({
        "phase": "before_lease_retirement",
        "canonical_snapshot_sha256": before_retirement.snapshot_sha256,
        "matches_approved_snapshot": true,
    }));
    let retirement = match proof.lease.retire_after_terminal_receipt(&receipt_evidence) {
        Ok(retirement) => retirement,
        Err(failure) => {
            let readback = proof.lease.terminal_evidence_readback(&receipt, None);
            return contextualize_post_create_receipt_failure(
                failure.result,
                provider_calls,
                lifecycle,
                readback,
                local_receipt_mutations + failure.local_namespace_mutations,
            );
        }
    };
    let final_readback = proof.lease.terminal_evidence_readback(&receipt, None);
    if final_readback.custody != D1TerminalCustodyNamespace::Retired
        || final_readback.receipt_persisted != Some(true)
    {
        return contextualize_post_create_receipt_failure(
            recovery_error(
                "d1.bootstrap_terminal_readback_failed",
                "terminal receipt and retired bootstrap custody did not survive exact descriptor-bound readback",
            ),
            provider_calls,
            lifecycle,
            final_readback,
            local_receipt_mutations + retirement.local_namespace_mutations,
        );
    }
    CallToolResult::structured(json!({
        "ok": true,
        "operation": D1_BOOTSTRAP_FINALIZE_OPERATION,
        "dry_run": false,
        "status": "bootstrap_terminal_complete",
        "replayed": !receipt_created && retirement.local_namespace_mutations == 0,
        "terminal_plan_sha256": terminal_plan_sha256,
        "terminal_receipt_sha256": receipt_evidence.payload_sha256,
        "migration_family": D1_BOOTSTRAP_LEASE_FAMILY,
        "approved_evidence": {
            "reconciliation_plan_sha256": expected_reconciliation_plan_sha256,
            "initializer_authority_sha256": expected_initializer_authority_sha256,
            "query_authority_sha256": expected_query_authority_sha256,
            "canonical_snapshot_sha256": expected_canonical_snapshot_sha256,
            "terminal_request_sha256": terminal_request_sha256,
            "terminal_attempt_sha256": terminal_attempt_sha256,
        },
        "retry_decision": "do_not_retry_initializer",
        "lease_decision": "retired",
        "lease_retained": false,
        "custody_status": "retired_evidence_verified",
        "provider_calls": provider_calls,
        "provider_read_lifecycle": lifecycle,
        "response_evidence": response_evidence,
        "provider_mutations": 0,
        "local_namespace_mutations": local_receipt_mutations + retirement.local_namespace_mutations,
    }))
}

fn bootstrap_abort_authorities() -> (String, String, String) {
    let protocol = sha256_bytes_hex(
        &serde_json::to_vec(&json!({
            "version": 1,
            "effect_assertion_id": "bootstrap_initializer_not_dispatched_v1",
            "lease_protocol": crate::d1_migration_lease::D1_BOOTSTRAP_INITIALIZER_DISPATCH_PROTOCOL,
            "dispatch_rule": "durable_attempt_marker_before_provider_dispatch",
        }))
        .expect("bootstrap abort protocol serialization is infallible"),
    );
    let query = sha256_bytes_hex(
        &serde_json::to_vec(&json!({
            "version": 1,
            "evidence": "exact_initializer_attempt_marker_stably_absent_under_guard",
            "physical_states": ["absent", "present", "malformed_or_contradictory"],
        }))
        .expect("bootstrap abort query serialization is infallible"),
    );
    let snapshot = sha256_bytes_hex(
        &serde_json::to_vec(&json!({
            "version": 1,
            "initializer_dispatch_state": "not_dispatched",
            "provider_initializer_dispatches": 0,
        }))
        .expect("bootstrap abort snapshot serialization is infallible"),
    );
    (protocol, query, snapshot)
}

#[allow(clippy::too_many_arguments)]
fn bootstrap_abort_terminal_plan_sha256(
    target_key_sha256: &str,
    migrations_table: &str,
    approved_bootstrap_plan_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
    protocol_authority_sha256: &str,
    marker_query_sha256: &str,
    zero_dispatch_snapshot_sha256: &str,
    terminal_request_sha256: &str,
    terminal_attempt_sha256: &str,
) -> String {
    sha256_bytes_hex(
        &serde_json::to_vec(&json!({
            "version": 1,
            "operation": D1_BOOTSTRAP_ABORT_OPERATION,
            "target_key_sha256": target_key_sha256,
            "migration_family": D1_BOOTSTRAP_LEASE_FAMILY,
            "migrations_table": migrations_table,
            "approved_bootstrap_plan_sha256": approved_bootstrap_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "protocol_authority_sha256": protocol_authority_sha256,
            "marker_query_sha256": marker_query_sha256,
            "zero_dispatch_snapshot_sha256": zero_dispatch_snapshot_sha256,
            "terminal_request_sha256": terminal_request_sha256,
            "terminal_attempt_sha256": terminal_attempt_sha256,
            "effect": "persist_zero_dispatch_terminal_receipt_then_retire_bootstrap_custody",
            "provider_calls": 0,
            "provider_mutations": 0,
        }))
        .expect("bootstrap abort terminal plan serialization is infallible"),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn abort_bootstrap_migration_ledger(
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    approved_bootstrap_plan_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
    terminal_request_sha256: &str,
    terminal_attempt_sha256: &str,
    dry_run: bool,
    approved_terminal_plan_sha256: Option<&str>,
) -> CallToolResult {
    let hashes = [
        approved_bootstrap_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
        terminal_request_sha256,
        terminal_attempt_sha256,
    ];
    if hashes.into_iter().any(|value| !valid_lower_sha256(value))
        || terminal_request_sha256 == terminal_attempt_sha256
        || (!dry_run
            && approved_terminal_plan_sha256.is_none_or(|value| !valid_lower_sha256(value)))
    {
        return contextualize_failure(
            recovery_error(
                "d1.bootstrap_abort_request_invalid",
                "zero-dispatch bootstrap retirement requires canonical distinct request and attempt digests plus exact custody identity",
            ),
            D1_BOOTSTRAP_ABORT_OPERATION,
            "contradictory",
            0,
            Vec::new(),
            "not_inspected",
            Value::Null,
            0,
        );
    }
    let initializer = d1_migrations_table_init_sql(migrations_table);
    let computed_plan =
        d1_bootstrap_plan_sha256(account_id, database_id, migrations_table, &initializer);
    if computed_plan != approved_bootstrap_plan_sha256 {
        return contextualize_failure(
            recovery_error(
                "d1.bootstrap_abort_plan_mismatch",
                "the supplied bootstrap plan does not reproduce the exact target, table, and initializer authority",
            ),
            D1_BOOTSTRAP_ABORT_OPERATION,
            "contradictory",
            0,
            Vec::new(),
            "not_inspected",
            Value::Null,
            0,
        );
    }
    let target_key_sha256 = sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes());
    let (protocol_authority_sha256, marker_query_sha256, zero_dispatch_snapshot_sha256) =
        bootstrap_abort_authorities();
    let terminal_plan_sha256 = bootstrap_abort_terminal_plan_sha256(
        &target_key_sha256,
        migrations_table,
        approved_bootstrap_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
        &protocol_authority_sha256,
        &marker_query_sha256,
        &zero_dispatch_snapshot_sha256,
        terminal_request_sha256,
        terminal_attempt_sha256,
    );
    if !dry_run && approved_terminal_plan_sha256 != Some(terminal_plan_sha256.as_str()) {
        return contextualize_failure(
            recovery_error(
                "d1.bootstrap_abort_terminal_plan_mismatch",
                "approved_terminal_plan_sha256 does not match this exact zero-dispatch retirement plan",
            ),
            D1_BOOTSTRAP_ABORT_OPERATION,
            "contradictory",
            0,
            Vec::new(),
            "not_inspected",
            Value::Null,
            0,
        );
    }
    let receipt = D1TerminalReconciliationReceipt {
        version: 2,
        operation: D1_BOOTSTRAP_ABORT_OPERATION.to_string(),
        target_key_sha256,
        lease_nonce: lease_nonce.to_string(),
        lease_payload_sha256: lease_payload_sha256.to_string(),
        approved_apply_plan_sha256: approved_bootstrap_plan_sha256.to_string(),
        effect_assertion_id: "bootstrap_initializer_not_dispatched_v1".to_string(),
        reconciliation_plan_sha256: protocol_authority_sha256.clone(),
        expectation_proof_sha256: protocol_authority_sha256.clone(),
        query_sha256: marker_query_sha256.clone(),
        canonical_snapshot_sha256: zero_dispatch_snapshot_sha256.clone(),
        terminal_request_sha256: terminal_request_sha256.to_string(),
        terminal_attempt_sha256: terminal_attempt_sha256.to_string(),
        terminal_plan_sha256: terminal_plan_sha256.clone(),
        outcome: "not_committed".to_string(),
        original_prefix_length: 0,
        current_prefix_length: 0,
    };
    let mut lease = match inspect_terminal_d1_migration_lease(
        account_id,
        database_id,
        D1_BOOTSTRAP_LEASE_FAMILY,
        approved_bootstrap_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
    ) {
        Ok(lease) => lease,
        Err(result) => {
            return contextualize_failure(
                result,
                D1_BOOTSTRAP_ABORT_OPERATION,
                "contradictory",
                0,
                Vec::new(),
                "inspection_failed",
                Value::Null,
                0,
            );
        }
    };
    if let Err(result) = lease.prove_bootstrap_initializer_not_dispatched() {
        return contextualize_failure(
            result,
            D1_BOOTSTRAP_ABORT_OPERATION,
            "contradictory",
            0,
            Vec::new(),
            custody_status(&lease),
            terminal_lease_retained(&lease),
            0,
        );
    }
    let receipt_state = match lease.terminal_receipt_state(&receipt) {
        Ok(receipt) => receipt,
        Err(result) => {
            return contextualize_failure(
                result,
                D1_BOOTSTRAP_ABORT_OPERATION,
                "contradictory",
                0,
                Vec::new(),
                custody_status(&lease),
                terminal_lease_retained(&lease),
                0,
            );
        }
    };
    if lease.is_retired() {
        return match receipt_state {
            Some(evidence) => CallToolResult::structured(json!({
                "ok": true,
                "operation": D1_BOOTSTRAP_ABORT_OPERATION,
                "dry_run": dry_run,
                "status": "bootstrap_zero_dispatch_abort_already_complete",
                "replayed": true,
                "terminal_plan_sha256": terminal_plan_sha256,
                "terminal_receipt_sha256": evidence.payload_sha256,
                "initializer_dispatch_state": "not_dispatched",
                "provider_initializer_dispatches": 0,
                "retry_decision": "fresh_bootstrap_requires_new_dry_run",
                "lease_decision": "retired",
                "lease_retained": false,
                "custody_status": "retired_evidence_verified",
                "provider_calls": 0,
                "provider_read_lifecycle": [],
                "response_evidence": [],
                "provider_mutations": 0,
                "local_namespace_mutations": 0,
            })),
            None => contextualize_failure(
                recovery_error(
                    "d1.bootstrap_abort_terminal_receipt_absent",
                    "retired bootstrap custody exists without its exact zero-dispatch terminal receipt",
                ),
                D1_BOOTSTRAP_ABORT_OPERATION,
                "contradictory",
                0,
                Vec::new(),
                "retired_evidence_verified",
                json!(false),
                0,
            ),
        };
    }
    if lease.identity.namespace == "retiring" && receipt_state.is_none() {
        return contextualize_failure(
            recovery_error(
                "d1.bootstrap_abort_terminal_receipt_absent",
                "bootstrap custody entered retiring state without its exact zero-dispatch terminal receipt",
            ),
            D1_BOOTSTRAP_ABORT_OPERATION,
            "contradictory",
            0,
            Vec::new(),
            "retiring_evidence_verified",
            Value::Null,
            0,
        );
    }
    if dry_run {
        return CallToolResult::structured(json!({
            "ok": true,
            "operation": D1_BOOTSTRAP_ABORT_OPERATION,
            "dry_run": true,
            "status": "bootstrap_zero_dispatch_abort_plan_ready",
            "terminal_plan_sha256": terminal_plan_sha256,
            "initializer_dispatch_state": "not_dispatched",
            "provider_initializer_dispatches": 0,
            "evidence": {
                "protocol_authority_sha256": protocol_authority_sha256,
                "marker_query_sha256": marker_query_sha256,
                "zero_dispatch_snapshot_sha256": zero_dispatch_snapshot_sha256,
            },
            "retry_decision": "fresh_bootstrap_requires_new_dry_run",
            "lease_decision": if lease.identity.namespace == "active" { json!("retain_until_approved_terminal_call") } else { Value::Null },
            "lease_retained": terminal_lease_retained(&lease),
            "custody_status": custody_status(&lease),
            "provider_calls": 0,
            "provider_read_lifecycle": [],
            "response_evidence": [],
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
        }));
    }
    let (receipt_evidence, receipt_created) = match lease.persist_terminal_receipt(&receipt) {
        Ok(receipt) => receipt,
        Err(failure) => {
            if failure.local_namespace_mutations > 0 {
                let readback = lease.terminal_evidence_readback(&receipt, None);
                return contextualize_abort_post_create_failure(
                    failure.result,
                    "unknown",
                    readback,
                    failure.local_namespace_mutations,
                );
            }
            return contextualize_failure(
                failure.result,
                D1_BOOTSTRAP_ABORT_OPERATION,
                "unknown",
                0,
                Vec::new(),
                custody_status(&lease),
                terminal_lease_retained(&lease),
                failure.local_namespace_mutations,
            );
        }
    };
    if let Err(result) = lease.prove_bootstrap_initializer_not_dispatched() {
        let readback = lease.terminal_evidence_readback(&receipt, None);
        return contextualize_abort_post_create_failure(
            result,
            "contradictory",
            readback,
            usize::from(receipt_created),
        );
    }
    let retirement = match lease.retire_after_terminal_receipt(&receipt_evidence) {
        Ok(retirement) => retirement,
        Err(failure) => {
            let readback = lease.terminal_evidence_readback(&receipt, None);
            return contextualize_abort_post_create_failure(
                failure.result,
                "unknown",
                readback,
                usize::from(receipt_created) + failure.local_namespace_mutations,
            );
        }
    };
    let final_readback = lease.terminal_evidence_readback(&receipt, None);
    if final_readback.custody != D1TerminalCustodyNamespace::Retired
        || final_readback.receipt_persisted != Some(true)
    {
        return contextualize_abort_post_create_failure(
            recovery_error(
                "d1.bootstrap_abort_terminal_readback_failed",
                "zero-dispatch terminal receipt and retired bootstrap custody did not survive exact readback",
            ),
            "unknown",
            final_readback,
            usize::from(receipt_created) + retirement.local_namespace_mutations,
        );
    }
    CallToolResult::structured(json!({
        "ok": true,
        "operation": D1_BOOTSTRAP_ABORT_OPERATION,
        "dry_run": false,
        "status": "bootstrap_zero_dispatch_abort_complete",
        "replayed": !receipt_created && retirement.local_namespace_mutations == 0,
        "terminal_plan_sha256": terminal_plan_sha256,
        "terminal_receipt_sha256": receipt_evidence.payload_sha256,
        "initializer_dispatch_state": "not_dispatched",
        "provider_initializer_dispatches": 0,
        "retry_decision": "fresh_bootstrap_requires_new_dry_run",
        "lease_decision": "retired",
        "lease_retained": false,
        "custody_status": "retired_evidence_verified",
        "provider_calls": 0,
        "provider_read_lifecycle": [],
        "response_evidence": [],
        "provider_mutations": 0,
        "local_namespace_mutations": usize::from(receipt_created) + retirement.local_namespace_mutations,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_authority_digests_bind_table_initializer_and_queries() {
        assert_ne!(
            initializer_authority_sha256("d1_migrations"),
            initializer_authority_sha256("other_migrations")
        );
        assert_ne!(
            query_authority_sha256("d1_migrations"),
            query_authority_sha256("other_migrations")
        );
    }

    #[test]
    fn response_evidence_requires_captured_body_bytes() {
        let evidence = response_evidence_from_lifecycle(&[
            json!({
                "phase": "pre_dispatch",
                "query_sha256": "a".repeat(64),
                "response": {
                    "body_sha256": null,
                    "body_size_bytes": null,
                    "parse_state": "unavailable",
                },
            }),
            json!({
                "phase": "response_received",
                "query_sha256": "b".repeat(64),
                "response": {
                    "body_sha256": "c".repeat(64),
                    "body_size_bytes": 2,
                    "parse_state": "decoded",
                },
            }),
        ]);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0]["phase"], "response_received");
    }

    #[test]
    fn reconciliation_never_claims_active_retention_for_retiring_custody() {
        assert_eq!(
            reconciliation_lease_fields("active"),
            (json!("retain_until_terminal_receipt"), json!(true))
        );
        assert_eq!(
            reconciliation_lease_fields("retiring"),
            (Value::Null, Value::Null)
        );
    }

    #[test]
    fn retirement_failure_after_receipt_preserves_receipt_truth() {
        let result = contextualize_post_receipt_failure(
            recovery_error("d1.test_retirement_failure", "retirement failed"),
            "unknown",
            16,
            Vec::new(),
            "retained_evidence_verified",
            Value::Null,
            1,
        );
        let content = result.structured_content.expect("structured failure");
        assert_eq!(content["receipt_persisted"], json!(true));
        assert_eq!(content["local_namespace_mutations"], json!(1));
    }

    #[test]
    fn bootstrap_retirement_failure_never_promotes_unverified_readback_to_retired() {
        let result = contextualize_post_create_receipt_failure(
            recovery_error(
                "d1.test_retirement_sync_failure",
                "retirement rename completed but durable readback failed",
            ),
            16,
            Vec::new(),
            D1TerminalEvidenceReadback {
                custody: D1TerminalCustodyNamespace::Unverified,
                receipt_persisted: None,
            },
            3,
        );
        let content = result.structured_content.expect("structured failure");
        assert_eq!(content["receipt_persisted"], Value::Null);
        assert_eq!(content["custody_status"], "retained_evidence_unverified");
        assert_ne!(content["custody_status"], "retired_evidence_verified");
        assert_eq!(content["lease_retained"], Value::Null);
        assert_eq!(content["local_namespace_mutations"], json!(3));
    }

    #[test]
    fn post_create_receipt_failure_uses_stable_descriptor_readback() {
        let proven = contextualize_post_create_receipt_failure(
            recovery_error("d1.test_post_create_failure", "post-create sync failed"),
            12,
            Vec::new(),
            D1TerminalEvidenceReadback {
                custody: D1TerminalCustodyNamespace::Active,
                receipt_persisted: Some(true),
            },
            1,
        );
        let proven = proven.structured_content.expect("structured failure");
        assert_eq!(proven["receipt_persisted"], json!(true));
        assert_eq!(proven["lease_retained"], json!(true));
        assert_eq!(proven["local_namespace_mutations"], json!(1));

        let unknown = contextualize_post_create_receipt_failure(
            recovery_error("d1.test_post_create_failure", "post-create sync failed"),
            12,
            Vec::new(),
            D1TerminalEvidenceReadback {
                custody: D1TerminalCustodyNamespace::Unverified,
                receipt_persisted: None,
            },
            1,
        );
        let unknown = unknown.structured_content.expect("structured failure");
        assert_eq!(unknown["receipt_persisted"], Value::Null);
        assert_eq!(unknown["lease_retained"], Value::Null);
    }

    #[test]
    fn final_readback_failure_reports_exact_missing_or_unstable_receipt_state() {
        let unstable = contextualize_post_create_receipt_failure(
            recovery_error("d1.test_final_readback_failure", "readback failed"),
            16,
            Vec::new(),
            D1TerminalEvidenceReadback {
                custody: D1TerminalCustodyNamespace::Unverified,
                receipt_persisted: None,
            },
            3,
        );
        let unstable = unstable.structured_content.expect("structured failure");
        assert_eq!(unstable["receipt_persisted"], Value::Null);
        assert_eq!(unstable["lease_retained"], Value::Null);

        let missing = contextualize_post_create_receipt_failure(
            recovery_error("d1.test_final_readback_failure", "readback failed"),
            16,
            Vec::new(),
            D1TerminalEvidenceReadback {
                custody: D1TerminalCustodyNamespace::Retired,
                receipt_persisted: Some(false),
            },
            3,
        );
        let missing = missing.structured_content.expect("structured failure");
        assert_eq!(missing["receipt_persisted"], json!(false));
        assert_eq!(missing["lease_retained"], json!(false));
        assert_eq!(missing["custody_status"], "retired_evidence_verified");
        assert_eq!(missing["local_namespace_mutations"], json!(3));
    }

    #[test]
    fn terminal_plan_binds_distinct_bootstrap_evidence_products() {
        let hash = "a".repeat(64);
        let first = terminal_plan_sha256(
            &hash,
            "d1_migrations",
            &hash,
            &"b".repeat(64),
            &"c".repeat(64),
            &"d".repeat(64),
            &"e".repeat(64),
            &"f".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
            &"3".repeat(64),
        );
        let second = terminal_plan_sha256(
            &hash,
            "d1_migrations",
            &hash,
            &"b".repeat(64),
            &"c".repeat(64),
            &"d".repeat(64),
            &"e".repeat(64),
            &"f".repeat(64),
            &"1".repeat(64),
            &"2".repeat(64),
            &"4".repeat(64),
        );
        assert_ne!(first, second);
    }
}
