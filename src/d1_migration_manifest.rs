//! Exact-byte D1 migration manifest parsing, digesting and reconciliation evidence.
//!
//! This module intentionally contains no tool registration. `tools` owns the
//! MCP boundary and provider-write orchestration; this module owns the
//! manifest proof products and reconciliation evidence.

use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

use crate::d1_migration_lease::D1MigrationLease;
use crate::server::CloudflareMcp;
use crate::tools::{
    D1MigrationManifestEntry, MAX_D1_MIGRATION_BYTES, MAX_D1_MIGRATION_COUNT,
    d1_applied_migrations_sql, d1_call_tool_error_value, invalid_argument_result, sha256_bytes_hex,
    sha256_hex,
};

#[derive(Debug, Clone)]
pub(crate) struct D1ManifestTarget {
    pub(crate) account_id: String,
    pub(crate) database_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct D1ManifestLedgerRow {
    pub(crate) id: i64,
    pub(crate) name: String,
}

#[derive(Debug, Clone)]
pub(crate) struct D1ManifestClassification {
    pub(crate) applied_names: Vec<String>,
    pub(crate) pending: Vec<D1MigrationManifestEntry>,
}

/// Evidence that must survive an operator-facing reconciliation result. A
/// ledger can be known and contradictory; that is deliberately distinct from
/// a ledger that could not be read or proved stable.
pub(crate) struct D1ManifestReconciliationEvidence<'a> {
    pub(crate) supplied_plan_sha256: Option<&'a str>,
    pub(crate) computed_plan_sha256: Option<&'a str>,
    pub(crate) ledger: Option<&'a [D1ManifestLedgerRow]>,
    pub(crate) unknown_ledger: bool,
}

impl<'a> D1ManifestReconciliationEvidence<'a> {
    pub(crate) fn new(
        supplied_plan_sha256: Option<&'a str>,
        computed_plan_sha256: Option<&'a str>,
        ledger: Option<&'a [D1ManifestLedgerRow]>,
        unknown_ledger: bool,
    ) -> Self {
        Self {
            supplied_plan_sha256,
            computed_plan_sha256,
            ledger,
            unknown_ledger,
        }
    }
}

pub(crate) fn normalize_d1_manifest_target(
    account_id: &str,
    database_id: &str,
) -> Result<D1ManifestTarget, CallToolResult> {
    fn normalize(label: &'static str, value: &str) -> Result<String, CallToolResult> {
        let trimmed = value.trim();
        if trimmed.is_empty()
            || trimmed != value
            || matches!(trimmed, "." | "..")
            || trimmed.len() > 256
            || trimmed.contains('\0')
        {
            return Err(invalid_argument_result(
                "d1.invalid_manifest_target_identity",
                format!(
                    "{label} must be a non-empty canonical identifier, not a dot path segment, and without surrounding whitespace"
                ),
                "Use the exact account_id and database_id read from the intended Cloudflare resource.",
            ));
        }
        Ok(trimmed.to_string())
    }
    Ok(D1ManifestTarget {
        account_id: normalize("account_id", account_id)?,
        database_id: normalize("database_id", database_id)?,
    })
}

pub(crate) fn normalize_d1_migration_family(value: &str) -> Result<String, CallToolResult> {
    let value = value.trim();
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'));
    if valid {
        Ok(value.to_string())
    } else {
        Err(invalid_argument_result(
            "d1.invalid_migration_family",
            "migration_family must be 1..128 ASCII letters, digits, '.', '_', '-', or ':' characters",
            "Use a stable operator-facing family label such as newsletter-core.",
        ))
    }
}

pub(crate) fn validate_d1_migration_manifest(
    manifest: Vec<D1MigrationManifestEntry>,
) -> Result<Vec<D1MigrationManifestEntry>, CallToolResult> {
    if manifest.is_empty() {
        return Err(invalid_argument_result(
            "d1.empty_migration_manifest",
            "manifest must contain at least one exact migration",
            "Provide the complete approved migration manifest in lexical Wrangler order.",
        ));
    }
    if manifest.len() > MAX_D1_MIGRATION_COUNT {
        return Err(invalid_argument_result(
            "d1.too_many_migrations",
            format!("manifest contains more than {MAX_D1_MIGRATION_COUNT} migrations"),
            "Apply a smaller complete migration family.",
        ));
    }
    let mut previous = None::<String>;
    for migration in &manifest {
        let name = migration.name.trim();
        if name != migration.name
            || name.is_empty()
            || name.len() > 255
            || !name.ends_with(".sql")
            || name.contains('/')
            || name.contains('\\')
            || name.contains('\0')
        {
            return Err(invalid_argument_result(
                "d1.invalid_manifest_migration_name",
                "manifest migration names must be non-empty .sql basenames of at most 255 bytes without path separators",
                "Use the exact Wrangler migration filename, for example 0001_initial.sql.",
            ));
        }
        if previous.as_deref().is_some_and(|prior| prior >= name) {
            return Err(invalid_argument_result(
                "d1.manifest_not_lexical",
                "manifest migration names must be unique and strictly lexical",
                "Supply the complete manifest in the same lexical order that Wrangler uses.",
            ));
        }
        if migration.size_bytes > MAX_D1_MIGRATION_BYTES
            || migration.size_bytes != migration.sql.as_bytes().len() as u64
        {
            return Err(invalid_argument_result(
                "d1.manifest_size_mismatch",
                "manifest size_bytes must equal the exact UTF-8 SQL byte length and stay within the migration limit",
                "Rebuild the manifest from the reviewed SQL bytes.",
            ));
        }
        if migration.sql.trim().is_empty() {
            return Err(invalid_argument_result(
                "d1.manifest_empty_sql",
                "manifest migration SQL must not be empty",
                "Provide the complete reviewed migration SQL bytes.",
            ));
        }
        let expected = sha256_hex(&migration.sql);
        if migration.sql_sha256.len() != 64
            || !migration
                .sql_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !migration.sql_sha256.eq_ignore_ascii_case(&expected)
        {
            return Err(invalid_argument_result(
                "d1.manifest_sha256_mismatch",
                "manifest sql_sha256 does not match the supplied exact SQL bytes",
                "Recompute SHA-256 from the same SQL string that will be applied.",
            ));
        }
        previous = Some(name.to_string());
    }
    Ok(manifest)
}

pub(crate) fn parse_d1_migration_ledger(
    value: &Value,
) -> Result<Vec<D1ManifestLedgerRow>, CallToolResult> {
    // CloudflareClient unwraps the v4 envelope's `result`, while direct test
    // fixtures may retain it. Accept exactly one D1 result set in either shape.
    let result_sets = value
        .is_array()
        .then_some(value)
        .or_else(|| value.get("result"));
    let results = result_sets
        .and_then(Value::as_array)
        .and_then(|items| (items.len() == 1).then_some(&items[0]))
        .and_then(|item| item.get("results"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            d1_manifest_malformed_ledger_result(
                "provider ledger response did not contain one result set",
            )
        })?;
    let mut ledger = Vec::with_capacity(results.len());
    let mut previous_id = None;
    let mut names = BTreeSet::new();
    for row in results {
        let object = row.as_object().ok_or_else(|| {
            d1_manifest_malformed_ledger_result("provider ledger row was not an object")
        })?;
        let id = object
            .get("id")
            .and_then(Value::as_i64)
            .filter(|id| *id >= 0)
            .ok_or_else(|| {
                d1_manifest_malformed_ledger_result(
                    "provider ledger row had no non-negative integer id",
                )
            })?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty() && name.len() <= 255 && !name.contains('\0'))
            .ok_or_else(|| {
                d1_manifest_malformed_ledger_result(
                    "provider ledger row had no valid migration name",
                )
            })?
            .to_string();
        if previous_id.is_some_and(|previous| previous >= id) || !names.insert(name.clone()) {
            return Err(d1_manifest_malformed_ledger_result(
                "provider ledger ids or migration names were duplicate or out of order",
            ));
        }
        previous_id = Some(id);
        ledger.push(D1ManifestLedgerRow { id, name });
    }
    Ok(ledger)
}

/// Accept only a non-empty sequence of complete, successful D1 query results
/// that lets the manifest coordinator claim a migration was applied. This is deliberately
/// stricter than the generic D1 query helper: a non-idempotent migration write
/// must treat a missing, malformed, or failed inner D1 result as an unknown
/// external outcome, rather than as a safe no-op or an applied statement.
pub(crate) fn validate_d1_manifest_write_result(value: &Value) -> Result<(), Value> {
    let result_sets = value.as_array().ok_or_else(|| {
        d1_manifest_ambiguous_write_evidence(
            "missing_or_non_array_result",
            "provider write response did not contain a D1 result-set array",
        )
    })?;
    if result_sets.is_empty() {
        return Err(d1_manifest_ambiguous_write_evidence(
            "empty_result_set_sequence",
            "provider write response did not contain any D1 result set",
        ));
    }
    for result_set in result_sets {
        let result_set = result_set.as_object().ok_or_else(|| {
            d1_manifest_ambiguous_write_evidence(
                "malformed_result_set",
                "provider write response result set was not an object",
            )
        })?;
        if result_set.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(d1_manifest_ambiguous_write_evidence(
                "inner_statement_failure_or_missing_success",
                "provider write response did not prove a successful inner D1 statement",
            ));
        }
        match result_set.get("errors") {
            Some(Value::Array(errors)) if !errors.is_empty() => {
                return Err(d1_manifest_ambiguous_write_evidence(
                    "inner_statement_error",
                    "provider write response included an inner D1 statement error",
                ));
            }
            None | Some(Value::Array(_)) => {}
            _ => {
                return Err(d1_manifest_ambiguous_write_evidence(
                    "malformed_inner_errors",
                    "provider write response contained a malformed inner D1 errors value",
                ));
            }
        }
        if !matches!(result_set.get("results"), Some(Value::Array(_))) {
            return Err(d1_manifest_ambiguous_write_evidence(
                "missing_or_malformed_inner_results",
                "provider write response did not contain an inner D1 results array",
            ));
        }
    }
    Ok(())
}

fn d1_manifest_ambiguous_write_evidence(
    classification: &'static str,
    message: &'static str,
) -> Value {
    json!({
        "code": "d1.migration_apply_result_ambiguous",
        "classification": classification,
        "message": message,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::validate_d1_manifest_write_result;

    #[test]
    fn manifest_write_result_requires_non_empty_complete_successful_inner_results() {
        assert!(
            validate_d1_manifest_write_result(&json!([
                {"success": true, "errors": [], "results": []}
            ]))
            .is_ok()
        );
        assert!(
            validate_d1_manifest_write_result(&json!([
                {"success": true, "errors": [], "results": []},
                {"success": true, "errors": [], "results": []}
            ]))
            .is_ok()
        );

        for (name, value, classification) in [
            ("missing", json!(null), "missing_or_non_array_result"),
            ("empty", json!([]), "empty_result_set_sequence"),
            ("null inner", json!([null]), "malformed_result_set"),
            (
                "missing inner results",
                json!([{"success": true, "errors": []}]),
                "missing_or_malformed_inner_results",
            ),
            (
                "null inner results",
                json!([{"success": true, "errors": [], "results": null}]),
                "missing_or_malformed_inner_results",
            ),
            (
                "malformed inner results",
                json!([{"success": true, "errors": [], "results": {}}]),
                "missing_or_malformed_inner_results",
            ),
            (
                "missing inner success",
                json!([{"errors": [], "results": []}]),
                "inner_statement_failure_or_missing_success",
            ),
            (
                "inner failure",
                json!([{"success": false, "errors": [], "results": []}]),
                "inner_statement_failure_or_missing_success",
            ),
            (
                "mixed inner success and failure",
                json!([
                    {"success": true, "errors": [], "results": []},
                    {"success": false, "errors": [], "results": []}
                ]),
                "inner_statement_failure_or_missing_success",
            ),
            (
                "inner error",
                json!([{"success": true, "errors": [{"code": 1}], "results": []}]),
                "inner_statement_error",
            ),
        ] {
            let error = validate_d1_manifest_write_result(&value)
                .expect_err("{name} must leave the write outcome unknown");
            assert_eq!(error["code"], "d1.migration_apply_result_ambiguous");
            assert_eq!(error["classification"], classification, "{name}");
        }
    }
}

fn d1_manifest_malformed_ledger_result(message: &'static str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_apply_migration_manifest",
        "status": "reconciliation_required",
        "unknown_ledger": true,
        "error": {
            "code": "d1.migration_ledger_malformed",
            "message": message,
            "hint": "Reconcile the exact provider migration ledger before applying migration SQL.",
        },
    }))
}

pub(crate) fn classify_d1_manifest_ledger(
    manifest: &[D1MigrationManifestEntry],
    ledger: &[D1ManifestLedgerRow],
) -> Result<D1ManifestClassification, CallToolResult> {
    if ledger.len() > manifest.len()
        || ledger
            .iter()
            .zip(manifest)
            .any(|(ledger_row, migration)| ledger_row.name != migration.name)
    {
        return Err(CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "d1_apply_migration_manifest",
            "status": "reconciliation_required",
            "unknown_ledger": false,
            "error": {
                "code": "d1.migration_ledger_not_manifest_prefix",
                "message": "provider migration ledger is not an exact prefix of the approved manifest",
                "hint": "Do not apply or skip migrations. Reconcile the provider ledger and use a complete matching manifest.",
            },
        })));
    }
    Ok(D1ManifestClassification {
        applied_names: ledger.iter().map(|row| row.name.clone()).collect(),
        pending: manifest[ledger.len()..].to_vec(),
    })
}

pub(crate) fn d1_manifest_summaries(manifest: &[D1MigrationManifestEntry]) -> Vec<Value> {
    manifest
        .iter()
        .map(|migration| {
            json!({
                "name": migration.name,
                "size_bytes": migration.size_bytes,
                "sql_sha256": migration.sql_sha256.to_ascii_lowercase(),
            })
        })
        .collect()
}

pub(crate) fn d1_ledger_summaries(ledger: &[D1ManifestLedgerRow]) -> Vec<Value> {
    ledger
        .iter()
        .map(|row| json!({"id": row.id, "name": row.name}))
        .collect()
}

pub(crate) fn d1_manifest_plan_sha256(
    account_id: &str,
    database_id: &str,
    family: &str,
    migrations_table: &str,
    manifest: &[D1MigrationManifestEntry],
    ledger: &[D1ManifestLedgerRow],
) -> String {
    #[derive(Serialize)]
    struct Plan<'a> {
        version: u8,
        operation: &'static str,
        account_id: &'a str,
        database_id: &'a str,
        migration_family: &'a str,
        migrations_table: &'a str,
        manifest: Vec<Value>,
        ledger: Vec<Value>,
    }
    let bytes = serde_json::to_vec(&Plan {
        version: 1,
        operation: "d1_apply_migration_manifest",
        account_id,
        database_id,
        migration_family: family,
        migrations_table,
        manifest: d1_manifest_summaries(manifest),
        ledger: d1_ledger_summaries(ledger),
    })
    .expect("serializing D1 manifest plan is infallible");
    sha256_bytes_hex(&bytes)
}

pub(crate) fn approved_d1_plan_digest_matches(provided: Option<&str>, expected: &str) -> bool {
    provided
        .map(str::trim)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
}

pub(crate) fn d1_manifest_plan_mismatch_result(
    account_id: &str,
    database_id: &str,
    family: &str,
    migrations_table: &str,
    manifest: &[D1MigrationManifestEntry],
    ledger: &[D1ManifestLedgerRow],
    computed_plan_sha256: &str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_apply_migration_manifest",
        "account_id": account_id,
        "database_id": database_id,
        "migration_family": family,
        "migrations_table": migrations_table,
        "manifest": d1_manifest_summaries(manifest),
        "ledger": d1_ledger_summaries(ledger),
        "computed_plan_sha256": computed_plan_sha256,
        "error": {
            "code": "d1.migration_plan_digest_mismatch",
            "message": "live apply requires the exact approved plan_sha256 from a dry run against this current ledger",
            "hint": "Run dry_run=true, record its plan_sha256, then use that exact value for one live apply under the shared target lease.",
        },
    }))
}

pub(crate) async fn read_stable_d1_migration_ledger(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
) -> Result<Vec<D1ManifestLedgerRow>, CallToolResult> {
    let first = server
        .cloudflare
        .query_d1_database(
            account_id,
            database_id,
            &d1_applied_migrations_sql(migrations_table),
            &[],
        )
        .await
        .map_err(|error| {
            d1_manifest_unknown_ledger_result(
                account_id,
                database_id,
                "",
                migrations_table,
                &[],
                error.payload(),
            )
        })
        .and_then(|value| parse_d1_migration_ledger(&value))?;
    let second = server
        .cloudflare
        .query_d1_database(
            account_id,
            database_id,
            &d1_applied_migrations_sql(migrations_table),
            &[],
        )
        .await
        .map_err(|error| {
            d1_manifest_unknown_ledger_result(
                account_id,
                database_id,
                "",
                migrations_table,
                &[],
                error.payload(),
            )
        })
        .and_then(|value| parse_d1_migration_ledger(&value))?;
    if first != second {
        return Err(CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "d1_apply_migration_manifest",
            "status": "reconciliation_required",
            "unknown_ledger": true,
            "error": {"code": "d1.migration_ledger_unstable", "message": "two terminal provider ledger readbacks disagreed", "hint": "Reconcile concurrent or external migration activity before clearing the retained lease."},
        })));
    }
    Ok(first)
}

pub(crate) fn d1_manifest_unknown_ledger_result(
    account_id: &str,
    database_id: &str,
    family: &str,
    migrations_table: &str,
    manifest: &[D1MigrationManifestEntry],
    error: crate::cloudflare::AdapterErrorPayload,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_apply_migration_manifest",
        "account_id": account_id,
        "database_id": database_id,
        "migration_family": family,
        "migrations_table": migrations_table,
        "manifest": d1_manifest_summaries(manifest),
        "status": "reconciliation_required",
        "unknown_ledger": true,
        "error": {"code": "d1.migration_ledger_unreadable", "message": "could not read the D1 migration ledger; migration SQL was not executed", "hint": "Reconcile provider ledger access and state before applying migration SQL.", "cause": error},
    }))
}

pub(crate) fn d1_manifest_reconciliation_required_result(
    account_id: &str,
    database_id: &str,
    family: &str,
    migrations_table: &str,
    manifest: &[D1MigrationManifestEntry],
    supplied_plan_sha256: Option<&str>,
    plan_sha256: &str,
    migration: &D1MigrationManifestEntry,
    applied: &[Value],
    last_known_ledger: &[D1ManifestLedgerRow],
    reconciled_ledger: Option<&[D1ManifestLedgerRow]>,
    lease: &D1MigrationLease,
    error: Value,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_apply_migration_manifest",
        "account_id": account_id,
        "database_id": database_id,
        "migration_family": family,
        "migrations_table": migrations_table,
        "manifest": d1_manifest_summaries(manifest),
        "supplied_plan_sha256": supplied_plan_sha256,
        "computed_plan_sha256": plan_sha256,
        "status": "reconciliation_required",
        "outcome": "unknown",
        "unknown_ledger": reconciled_ledger.is_none(),
        "ledger_evidence": {
            "state": if reconciled_ledger.is_some() { "known" } else { "unknown" },
            "last_known_ledger": d1_ledger_summaries(last_known_ledger),
            "reconciled_ledger": reconciled_ledger.map(d1_ledger_summaries),
        },
        "exact_provider_evidence": {
            "state": "unavailable",
            "reason": "a migration filename in the provider ledger does not attest to the reviewed SQL bytes or the complete provider transaction",
        },
        "migration": {"name": migration.name, "sql_sha256": migration.sql_sha256.to_ascii_lowercase()},
        "applied_migrations": applied,
        "lease_retained": true,
        "lease": lease.identity,
        "operator_handoff": "Reconcile the named provider ledger and this lease owner identity before any subsequent apply. Do not replay a migration from this response.",
        "error": {"code": "d1.migration_apply_outcome_unknown", "message": "provider response after a migration apply was ambiguous; no retry or later migration was attempted", "hint": "Reconcile provider evidence and the exact ledger before clearing the retained target lease.", "cause": error},
    }))
}

pub(crate) fn d1_manifest_contextualize_failure(
    result: CallToolResult,
    account_id: &str,
    database_id: &str,
    family: &str,
    migrations_table: &str,
    manifest: &[D1MigrationManifestEntry],
    evidence: D1ManifestReconciliationEvidence<'_>,
    lease: &D1MigrationLease,
    lease_retained: bool,
) -> CallToolResult {
    let error = d1_call_tool_error_value(result);
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_apply_migration_manifest",
        "account_id": account_id,
        "database_id": database_id,
        "migration_family": family,
        "migrations_table": migrations_table,
        "manifest": d1_manifest_summaries(manifest),
        "supplied_plan_sha256": evidence.supplied_plan_sha256,
        "computed_plan_sha256": evidence.computed_plan_sha256,
        "status": "reconciliation_required",
        "unknown_ledger": evidence.unknown_ledger,
        "ledger_evidence": {
            "state": if evidence.unknown_ledger { "unknown" } else { "known" },
            "ledger": evidence.ledger.map(d1_ledger_summaries),
        },
        "lease_retained": lease_retained,
        "lease": lease.identity,
        "operator_handoff": "Reconcile the named provider ledger and this lease owner identity before any subsequent apply. Do not replay a migration from this response.",
        "error": error,
    }))
}
