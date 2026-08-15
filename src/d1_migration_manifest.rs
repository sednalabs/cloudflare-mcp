//! Exact-byte D1 migration manifest parsing, digesting and reconciliation evidence.
//!
//! This module intentionally contains no tool registration. `tools` owns the
//! MCP boundary and provider-write orchestration; this module owns the
//! manifest proof products and reconciliation evidence.

use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

use crate::d1_migration_lease::D1MigrationLease;
use crate::server::CloudflareMcp;
use crate::tools::{
    D1MigrationManifestEntry, MAX_D1_MIGRATION_BYTES, MAX_D1_MIGRATION_COUNT,
    MAX_D1_MIGRATION_MANIFEST_BYTES, d1_applied_migrations_sql, d1_call_tool_error_value,
    invalid_argument_result, sha256_bytes_hex, sha256_hex,
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

/// Read-only authority for the table which records manifest application.
///
/// The manifest apply path appends to this table.  A successful `SELECT *`
/// alone is not enough to establish that it is still the intended ledger: a
/// view, a case-insensitive sibling, or a trigger targeting the table could
/// make the following provider write mean something materially different.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1ManifestLedgerAuthority {
    table_sql: String,
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
    let mut manifest_size_bytes = 0_u64;
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
        manifest_size_bytes = manifest_size_bytes
            .checked_add(migration.size_bytes)
            .ok_or_else(|| {
                invalid_argument_result(
                    "d1.migration_manifest_too_large",
                    "manifest aggregate SQL byte length overflowed the supported bound",
                    "Apply a smaller complete migration family.",
                )
            })?;
        if manifest_size_bytes > MAX_D1_MIGRATION_MANIFEST_BYTES {
            return Err(invalid_argument_result(
                "d1.migration_manifest_too_large",
                format!(
                    "manifest exact SQL bytes exceed the {MAX_D1_MIGRATION_MANIFEST_BYTES}-byte aggregate limit"
                ),
                "Apply a smaller complete migration family.",
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
    // CloudflareClient unwraps the v4 envelope's `result`, while callers that
    // preserve raw provider evidence retain that envelope. Accept exactly one
    // D1 result set in either shape, but never let a retained unsuccessful or
    // contradictory envelope be mistaken for a clean ledger read.
    let result_sets = if value.is_array() {
        value
    } else {
        let envelope = value.as_object().ok_or_else(|| {
            d1_manifest_malformed_ledger_result(
                "provider ledger response was neither an unwrapped result-set array nor an envelope object",
            )
        })?;
        if envelope.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(d1_manifest_malformed_ledger_result(
                "provider ledger envelope did not explicitly prove success",
            ));
        }
        match envelope.get("errors") {
            Some(Value::Array(errors)) if !errors.is_empty() => {
                return Err(d1_manifest_malformed_ledger_result(
                    "provider ledger envelope included contradictory errors",
                ));
            }
            None | Some(Value::Array(_)) => {}
            _ => {
                return Err(d1_manifest_malformed_ledger_result(
                    "provider ledger envelope had malformed errors",
                ));
            }
        }
        envelope.get("result").ok_or_else(|| {
            d1_manifest_malformed_ledger_result(
                "provider ledger envelope did not contain a result-set array",
            )
        })?
    };
    let result_set = result_sets
        .as_array()
        .and_then(|items| (items.len() == 1).then_some(&items[0]))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            d1_manifest_malformed_ledger_result(
                "provider ledger response did not contain one result-set object",
            )
        })?;
    if result_set.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(d1_manifest_malformed_ledger_result(
            "provider ledger result set did not explicitly prove success",
        ));
    }
    match result_set.get("errors") {
        Some(Value::Array(errors)) if !errors.is_empty() => {
            return Err(d1_manifest_malformed_ledger_result(
                "provider ledger result set included contradictory statement errors",
            ));
        }
        None | Some(Value::Array(_)) => {}
        _ => {
            return Err(d1_manifest_malformed_ledger_result(
                "provider ledger result set had malformed statement errors",
            ));
        }
    }
    // Migration names are operational authority only when the result set
    // explicitly came from D1's primary. A replica response can be internally
    // well-formed yet lag a concurrent migration, so it cannot support a plan,
    // apply, reconciliation, or successful release decision. The manifest
    // client decodes this response with duplicate-key rejection before it
    // reaches this parser.
    if result_set
        .get("meta")
        .and_then(Value::as_object)
        .and_then(|meta| meta.get("served_by_primary"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(d1_manifest_malformed_ledger_result(
            "provider ledger result set did not explicitly prove it was served by the D1 primary",
        ));
    }
    let results = result_set
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            d1_manifest_malformed_ledger_result(
                "provider ledger result set did not contain a results array",
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

fn quote_sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn quote_sql_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// The sole supported initializer for the reserved migration ledger.
pub(crate) fn d1_migrations_table_init_sql(table: &str) -> String {
    let table = quote_sql_identifier(table);
    format!(
        "CREATE TABLE IF NOT EXISTS {table}(\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    name TEXT UNIQUE,\n    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL\n);"
    )
}

/// The exact SQLite-master spelling derived from this MCP's compatible ledger
/// initializer. SQLite removes `IF NOT EXISTS` and the terminating semicolon
/// while preserving the remaining text, including indentation.
fn expected_d1_migration_ledger_table_sql(table: &str) -> String {
    d1_migrations_table_init_sql(table)
        .strip_suffix(';')
        .expect("reserved migration-ledger initializer has one trailing semicolon")
        .replacen("CREATE TABLE IF NOT EXISTS", "CREATE TABLE", 1)
}

// Wrangler 4.87.0 `src/d1/migrations/apply.ts` interpolates the already
// validated configured table identifier into this source form. SQLite retains
// that unquoted, case-preserving identifier and the tab alignment in
// `sqlite_master.sql`. Keep this as a closed accepted form rather than
// normalizing arbitrary SQL: the helper-generated spelling remains accepted,
// but an extra constraint, column, statement, or changed default never does.
fn wrangler_d1_migration_ledger_table_sql(table: &str) -> Option<String> {
    let mut characters = table.chars();
    let valid_identifier = matches!(characters.next(), Some(ch) if ch == '_' || ch.is_ascii_alphabetic())
        && characters.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && table.len() <= 64;
    valid_identifier.then(|| {
        format!(
            "CREATE TABLE {table}(\n\t\tid         INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tname       TEXT UNIQUE,\n\t\tapplied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL\n)"
        )
    })
}

fn is_supported_d1_migration_ledger_table_sql(table_sql: &str, table: &str) -> bool {
    table_sql == expected_d1_migration_ledger_table_sql(table)
        || wrangler_d1_migration_ledger_table_sql(table).as_deref() == Some(table_sql)
}

pub(crate) fn d1_migration_ledger_authority_sql(table: &str) -> String {
    let table = quote_sql_string(table);
    format!(
        "SELECT type, name, tbl_name, sql FROM sqlite_master \
         WHERE lower(name) = lower({table}) \
            OR (type = 'trigger' AND lower(tbl_name) = lower({table})) \
         ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'trigger' THEN 1 ELSE 2 END, name COLLATE BINARY"
    )
}

fn d1_manifest_ledger_authority_result(
    code: &'static str,
    message: &'static str,
    hint: &'static str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_apply_migration_manifest",
        "status": "reconciliation_required",
        "unknown_ledger": true,
        "ledger_authority": "unverified",
        "error": {"code": code, "message": message, "hint": hint},
    }))
}

fn authority_result_set<'a>(value: &'a Value) -> Result<&'a Vec<Value>, CallToolResult> {
    let result_sets = value.as_array().ok_or_else(|| {
        d1_manifest_ledger_authority_result(
            "d1.migration_ledger_authority_malformed",
            "provider ledger-authority response did not contain a result-set array",
            "Reconcile the exact migration-ledger schema and primary readback before applying migration SQL.",
        )
    })?;
    let result_set = if result_sets.len() == 1 {
        result_sets[0].as_object()
    } else {
        None
    }
    .ok_or_else(|| {
            d1_manifest_ledger_authority_result(
                "d1.migration_ledger_authority_malformed",
                "provider ledger-authority response did not contain exactly one result set",
                "Reconcile the exact migration-ledger schema and primary readback before applying migration SQL.",
            )
        })?;
    let errors_are_clean = match result_set.get("errors") {
        None => true,
        Some(Value::Array(errors)) => errors.is_empty(),
        _ => false,
    };
    if result_set.get("success").and_then(Value::as_bool) != Some(true) || !errors_are_clean {
        return Err(d1_manifest_ledger_authority_result(
            "d1.migration_ledger_authority_malformed",
            "provider ledger-authority result did not explicitly prove one successful statement without errors",
            "Reconcile the exact migration-ledger schema and primary readback before applying migration SQL.",
        ));
    }
    if result_set
        .get("meta")
        .and_then(Value::as_object)
        .and_then(|meta| meta.get("served_by_primary"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(d1_manifest_ledger_authority_result(
            "d1.migration_ledger_authority_not_primary",
            "provider ledger-authority readback did not explicitly prove it was served by the D1 primary",
            "Reconcile the migration ledger against an explicit primary readback before applying migration SQL.",
        ));
    }
    result_set.get("results").and_then(Value::as_array).ok_or_else(|| {
        d1_manifest_ledger_authority_result(
            "d1.migration_ledger_authority_malformed",
            "provider ledger-authority result did not contain a results array",
            "Reconcile the exact migration-ledger schema and primary readback before applying migration SQL.",
        )
    })
}

pub(crate) fn parse_d1_migration_ledger_authority(
    value: &Value,
    migrations_table: &str,
) -> Result<D1ManifestLedgerAuthority, CallToolResult> {
    let rows = authority_result_set(value)?;
    if rows.len() != 1 {
        return Err(d1_manifest_ledger_authority_result(
            "d1.migration_ledger_authority_invalid",
            "provider ledger-authority readback did not contain exactly one canonical ledger table and no ledger triggers",
            "Reconcile the migration-ledger table, case-equivalent objects, and trigger authority before applying migration SQL.",
        ));
    }
    let row = rows[0].as_object().ok_or_else(|| {
        d1_manifest_ledger_authority_result(
            "d1.migration_ledger_authority_malformed",
            "provider ledger-authority row was not an object",
            "Reconcile the exact migration-ledger schema and primary readback before applying migration SQL.",
        )
    })?;
    if row.len() != 4
        || row.get("type").and_then(Value::as_str) != Some("table")
        || row.get("name").and_then(Value::as_str) != Some(migrations_table)
        || row.get("tbl_name").and_then(Value::as_str) != Some(migrations_table)
    {
        return Err(d1_manifest_ledger_authority_result(
            "d1.migration_ledger_authority_invalid",
            "provider ledger-authority readback did not prove one exact configured ledger table without conflicting object or trigger evidence",
            "Reconcile the migration-ledger table, case-equivalent objects, and trigger authority before applying migration SQL.",
        ));
    }
    let table_sql = row.get("sql").and_then(Value::as_str).ok_or_else(|| {
        d1_manifest_ledger_authority_result(
            "d1.migration_ledger_authority_malformed",
            "provider ledger-authority table SQL was not text",
            "Reconcile the exact migration-ledger schema and primary readback before applying migration SQL.",
        )
    })?;
    if !is_supported_d1_migration_ledger_table_sql(table_sql, migrations_table) {
        return Err(d1_manifest_ledger_authority_result(
            "d1.migration_ledger_authority_invalid",
            "provider ledger-authority table SQL did not match the required canonical migration-ledger schema",
            "Reconcile or restore the exact migration-ledger schema before applying migration SQL.",
        ));
    }
    Ok(D1ManifestLedgerAuthority {
        table_sql: table_sql.to_string(),
    })
}

/// Accept only a non-empty sequence of primary-served, mutation-acknowledged
/// D1 results that lets the manifest coordinator claim a migration was
/// applied. This is deliberately stricter than the generic D1 query helper: a
/// non-idempotent migration write must treat a missing, malformed, or failed
/// inner D1 result as an unknown external outcome, rather than as a safe no-op
/// or an applied statement. The result rows themselves are normally empty for
/// DDL, so the mutation acknowledgement is the exact typed metadata contract:
/// every statement must report primary service and exact typed metadata, while
/// the whole response must prove at least one database change plus positive
/// changes and rows written. A non-mutating statement in a multi-statement
/// manifest (such as a supported PRAGMA) is therefore acceptable on its own
/// result set but cannot satisfy the aggregate proof.
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
    let mut total_changes = 0_u64;
    let mut total_rows_written = 0_u64;
    let mut changed_database = false;
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
        let meta = result_set
            .get("meta")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                d1_manifest_ambiguous_write_evidence(
                    "missing_or_malformed_write_metadata",
                    "provider write response did not contain exact D1 mutation metadata",
                )
            })?;
        if meta.get("served_by_primary").and_then(Value::as_bool) != Some(true) {
            return Err(d1_manifest_ambiguous_write_evidence(
                "write_not_served_by_primary",
                "provider write response did not explicitly prove it was served by the D1 primary",
            ));
        }
        let changed_db = meta
            .get("changed_db")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                d1_manifest_ambiguous_write_evidence(
                    "missing_or_malformed_write_metadata",
                    "provider write response did not contain a boolean changed_db acknowledgement",
                )
            })?;
        let changes = meta.get("changes").and_then(Value::as_u64).ok_or_else(|| {
            d1_manifest_ambiguous_write_evidence(
                "missing_or_malformed_write_metadata",
                "provider write response did not contain a non-negative integer changes count",
            )
        })?;
        let rows_written = meta
            .get("rows_written")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                d1_manifest_ambiguous_write_evidence(
                    "missing_or_malformed_write_metadata",
                    "provider write response did not contain a non-negative integer rows_written count",
                )
            })?;
        if !changed_db && (changes != 0 || rows_written != 0) {
            return Err(d1_manifest_ambiguous_write_evidence(
                "write_metadata_contradictory",
                "provider write result reported changed_db=false with nonzero mutation counts",
            ));
        }
        total_changes = total_changes.checked_add(changes).ok_or_else(|| {
            d1_manifest_ambiguous_write_evidence(
                "write_metadata_overflow",
                "provider write response changes counts overflowed the supported bound",
            )
        })?;
        total_rows_written = total_rows_written
            .checked_add(rows_written)
            .ok_or_else(|| {
                d1_manifest_ambiguous_write_evidence(
                    "write_metadata_overflow",
                    "provider write response rows_written counts overflowed the supported bound",
                )
            })?;
        changed_database |= changed_db;
    }
    if !changed_database {
        return Err(d1_manifest_ambiguous_write_evidence(
            "write_did_not_acknowledge_database_change",
            "provider write response did not prove that any result changed the database",
        ));
    }
    if total_changes == 0 || total_rows_written == 0 {
        return Err(d1_manifest_ambiguous_write_evidence(
            "write_metadata_did_not_prove_mutation",
            "provider write response did not prove at least one changed row and one row written",
        ));
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

    use super::{
        d1_manifest_write_result_classification, d1_migrations_table_init_sql,
        expected_d1_migration_ledger_table_sql, parse_d1_migration_ledger,
        parse_d1_migration_ledger_authority, validate_d1_manifest_write_result,
        wrangler_d1_migration_ledger_table_sql,
    };

    fn authority(table: &str) -> serde_json::Value {
        json!([{
            "success": true,
            "errors": [],
            "meta": {"served_by_primary": true},
            "results": [{
                "type": "table",
                "name": table,
                "tbl_name": table,
                "sql": expected_d1_migration_ledger_table_sql(table),
            }],
        }])
    }

    fn wrangler_authority(table: &str) -> serde_json::Value {
        json!([{
            "success": true,
            "errors": [],
            "meta": {"served_by_primary": true},
            "results": [{
                "type": "table",
                "name": table,
                "tbl_name": table,
                "sql": wrangler_d1_migration_ledger_table_sql(table)
                    .expect("test table is a valid Wrangler identifier"),
            }],
        }])
    }

    #[test]
    fn manifest_ledger_authority_requires_one_exact_primary_table_without_triggers() {
        assert!(
            parse_d1_migration_ledger_authority(&authority("d1_migrations"), "d1_migrations")
                .is_ok()
        );

        let mut cases = Vec::new();
        for (label, value) in [
            ("null response", json!(null)),
            ("object response", json!({})),
            ("primitive response", json!(1)),
            ("empty result sets", json!([])),
            ("null result set", json!([null])),
        ] {
            cases.push((label, value, "d1.migration_ledger_authority_malformed"));
        }
        cases.push((
            "missing primary",
            json!([{
                "success": true, "errors": [], "results": []
            }]),
            "d1.migration_ledger_authority_not_primary",
        ));
        cases.push((
            "non-primary",
            json!([{
                "success": true, "errors": [], "meta": {"served_by_primary": false}, "results": []
            }]),
            "d1.migration_ledger_authority_not_primary",
        ));
        cases.push(("wrong schema", json!([{
            "success": true, "errors": [], "meta": {"served_by_primary": true}, "results": [{
                "type": "table", "name": "d1_migrations", "tbl_name": "d1_migrations", "sql": "CREATE TABLE d1_migrations(id INTEGER)"
            }]
        }]), "d1.migration_ledger_authority_invalid"));
        cases.push(("wrong type", json!([{
            "success": true, "errors": [], "meta": {"served_by_primary": true}, "results": [{
                "type": "view", "name": "d1_migrations", "tbl_name": "d1_migrations", "sql": "CREATE VIEW d1_migrations AS SELECT 1"
            }]
        }]), "d1.migration_ledger_authority_invalid"));
        cases.push(("wrong target", json!([{
            "success": true, "errors": [], "meta": {"served_by_primary": true}, "results": [{
                "type": "table", "name": "d1_migrations", "tbl_name": "other_table", "sql": expected_d1_migration_ledger_table_sql("d1_migrations")
            }]
        }]), "d1.migration_ledger_authority_invalid"));
        cases.push(("non-text SQL", json!([{
            "success": true, "errors": [], "meta": {"served_by_primary": true}, "results": [{
                "type": "table", "name": "d1_migrations", "tbl_name": "d1_migrations", "sql": null
            }]
        }]), "d1.migration_ledger_authority_malformed"));
        let mut duplicate = authority("d1_migrations");
        duplicate[0]["results"].as_array_mut().expect("results").push(json!({
            "type": "trigger", "name": "ledger_after_insert", "tbl_name": "d1_migrations", "sql": "CREATE TRIGGER ledger_after_insert AFTER INSERT ON d1_migrations BEGIN SELECT 1; END"
        }));
        cases.push((
            "ledger trigger",
            duplicate,
            "d1.migration_ledger_authority_invalid",
        ));

        for (label, value, code) in cases {
            let error =
                parse_d1_migration_ledger_authority(&value, "d1_migrations").expect_err(label);
            assert_eq!(
                error.structured_content.expect(label)["error"]["code"],
                code,
                "{label}"
            );
        }
    }

    #[test]
    fn manifest_ledger_authority_schema_is_derived_from_the_live_initializer() {
        let initialized = d1_migrations_table_init_sql("d1_migrations");
        let expected = expected_d1_migration_ledger_table_sql("d1_migrations");
        assert_eq!(
            expected,
            initialized
                .strip_suffix(';')
                .expect("initializer trailing semicolon")
                .replacen("CREATE TABLE IF NOT EXISTS", "CREATE TABLE", 1),
            "the authority proof must derive its SQLite-master SQL from the same initializer"
        );
        assert!(
            expected.contains("\n    id INTEGER PRIMARY KEY AUTOINCREMENT,"),
            "SQLite preserves the initializer indentation in sqlite_master"
        );
    }

    #[test]
    fn manifest_ledger_authority_accepts_only_installed_wrangler_schema_forms() {
        for table in [
            "d1_migrations",
            "custom_migrations",
            "CasePreserving_Ledger",
        ] {
            let wrangler = wrangler_authority(table);
            assert!(parse_d1_migration_ledger_authority(&wrangler, table).is_ok());
        }

        let wrangler_default = wrangler_authority("d1_migrations");

        for sql in [
            "CREATE TABLE d1_migrations(\n\t\tid INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tname TEXT UNIQUE,\n\t\tapplied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,\n\t\textra TEXT\n)",
            "CREATE TABLE other_migrations(\n\t\tid         INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tname       TEXT UNIQUE,\n\t\tapplied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL\n)",
            "CREATE TABLE d1_migrations(\n\t\tid         INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tname       TEXT UNIQUE,\n\t\tapplied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n)",
        ] {
            let mut malformed = wrangler_default.clone();
            malformed[0]["results"][0]["sql"] = json!(sql);
            let error = parse_d1_migration_ledger_authority(&malformed, "d1_migrations")
                .expect_err("only the helper and installed Wrangler forms are accepted");
            assert_eq!(
                error.structured_content.expect("structured error")["error"]["code"],
                "d1.migration_ledger_authority_invalid"
            );
        }

        let mut case_drift = wrangler_authority("CasePreserving_Ledger");
        case_drift[0]["results"][0]["sql"] = json!(
            "CREATE TABLE casepreserving_ledger(\n\t\tid         INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tname       TEXT UNIQUE,\n\t\tapplied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL\n)"
        );
        let error = parse_d1_migration_ledger_authority(&case_drift, "CasePreserving_Ledger")
            .expect_err("case drift must not be normalized");
        assert_eq!(
            error.structured_content.expect("structured error")["error"]["code"],
            "d1.migration_ledger_authority_invalid"
        );
    }

    #[test]
    fn manifest_write_result_classification_is_closed() {
        for value in [
            "missing_or_non_array_result",
            "empty_result_set_sequence",
            "malformed_result_set",
            "inner_statement_failure_or_missing_success",
            "inner_statement_error",
            "malformed_inner_errors",
            "missing_or_malformed_inner_results",
            "missing_or_malformed_write_metadata",
            "write_not_served_by_primary",
            "write_did_not_acknowledge_database_change",
            "write_metadata_contradictory",
            "write_metadata_overflow",
            "write_metadata_did_not_prove_mutation",
        ] {
            assert_eq!(d1_manifest_write_result_classification(value), Some(value));
        }
        assert_eq!(d1_manifest_write_result_classification("retry_now"), None);
    }

    #[test]
    fn manifest_write_result_requires_primary_mutation_metadata() {
        assert!(
            validate_d1_manifest_write_result(&json!([
                {"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": true, "changes": 1, "rows_written": 1}}
            ]))
            .is_ok()
        );
        assert!(
            validate_d1_manifest_write_result(&json!([
                {"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": false, "changes": 0, "rows_written": 0}},
                {"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": true, "changes": 1, "rows_written": 1}}
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
                    {"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": true, "changes": 1, "rows_written": 1}},
                    {"success": false, "errors": [], "results": []}
                ]),
                "inner_statement_failure_or_missing_success",
            ),
            (
                "inner error",
                json!([{"success": true, "errors": [{"code": 1}], "results": []}]),
                "inner_statement_error",
            ),
            (
                "missing metadata",
                json!([{"success": true, "errors": [], "results": []}]),
                "missing_or_malformed_write_metadata",
            ),
            (
                "replica metadata",
                json!([{"success": true, "errors": [], "results": [], "meta": {"served_by_primary": false, "changed_db": true, "changes": 1, "rows_written": 1}}]),
                "write_not_served_by_primary",
            ),
            (
                "non-boolean changed database metadata",
                json!([{"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": "true", "changes": 1, "rows_written": 1}}]),
                "missing_or_malformed_write_metadata",
            ),
            (
                "unchanged metadata",
                json!([{"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": false, "changes": 1, "rows_written": 1}}]),
                "write_metadata_contradictory",
            ),
            (
                "mixed contradictory non-mutating result",
                json!([
                    {"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": false, "changes": 1, "rows_written": 1}},
                    {"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": true, "changes": 0, "rows_written": 0}}
                ]),
                "write_metadata_contradictory",
            ),
            (
                "empty mutation counts",
                json!([{"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": true, "changes": 0, "rows_written": 0}}]),
                "write_metadata_did_not_prove_mutation",
            ),
        ] {
            let error = validate_d1_manifest_write_result(&value)
                .expect_err("{name} must leave the write outcome unknown");
            assert_eq!(error["code"], "d1.migration_apply_result_ambiguous");
            assert_eq!(error["classification"], classification, "{name}");
        }
    }

    #[test]
    fn manifest_ledger_requires_explicit_success_clean_errors_and_results_array() {
        let valid = json!([
            {"success": true, "errors": [], "meta": {"served_by_primary": true}, "results": [{"id": 1, "name": "0001_initial.sql"}]}
        ]);
        assert!(parse_d1_migration_ledger(&valid).is_ok());
        let wrapped = json!({"success": true, "errors": [], "result": valid});
        assert!(parse_d1_migration_ledger(&wrapped).is_ok());

        for (label, value) in [
            ("missing success", json!([{"results": []}])),
            ("false success", json!([{"success": false, "results": []}])),
            (
                "nonboolean success",
                json!([{"success": "true", "results": []}]),
            ),
            ("missing results", json!([{"success": true}])),
            ("null results", json!([{"success": true, "results": null}])),
            (
                "nonarray results",
                json!([{"success": true, "results": {}}]),
            ),
            (
                "contradictory errors",
                json!([{"success": true, "errors": [{"code": 1}], "results": []}]),
            ),
            (
                "malformed errors",
                json!([{"success": true, "errors": {}, "results": []}]),
            ),
            (
                "missing primary proof",
                json!([{"success": true, "errors": [], "results": []}]),
            ),
            (
                "false primary proof",
                json!([{"success": true, "errors": [], "meta": {"served_by_primary": false}, "results": []}]),
            ),
            (
                "nonboolean primary proof",
                json!([{"success": true, "errors": [], "meta": {"served_by_primary": "true"}, "results": []}]),
            ),
            (
                "wrapped missing envelope success",
                json!({"errors": [], "result": [{"success": true, "results": []}]}),
            ),
            (
                "wrapped false envelope success",
                json!({"success": false, "errors": [], "result": [{"success": true, "results": []}]}),
            ),
            (
                "wrapped nonboolean envelope success",
                json!({"success": "true", "errors": [], "result": [{"success": true, "results": []}]}),
            ),
            (
                "wrapped contradictory envelope errors",
                json!({"success": true, "errors": [{"code": 1}], "result": [{"success": true, "results": []}]}),
            ),
            (
                "wrapped malformed envelope errors",
                json!({"success": true, "errors": {}, "result": [{"success": true, "results": []}]}),
            ),
        ] {
            let error = parse_d1_migration_ledger(&value)
                .expect_err("{label} must fail closed before migration SQL");
            assert_eq!(
                error.structured_content.expect("structured error")["error"]["code"],
                "d1.migration_ledger_malformed",
                "{label}"
            );
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
        .query_d1_migration_manifest(
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
        .query_d1_migration_manifest(
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

/// Before a manifest apply creates local custody or issues migration SQL, make
/// two primary-served reads of the reserved ledger's schema authority.  This
/// is deliberately separate from the ordinary filename ledger read: the latter
/// cannot prove that a same-named view, case-equivalent object, schema drift,
/// or a trigger on the target will not change the meaning of the next write.
pub(crate) async fn read_stable_d1_migration_ledger_authority(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
) -> Result<D1ManifestLedgerAuthority, CallToolResult> {
    let read_once = || async {
        let value = server
            .cloudflare
            .query_d1_migration_manifest(
                account_id,
                database_id,
                &d1_migration_ledger_authority_sql(migrations_table),
                &[],
            )
            .await
            .map_err(|_| {
                d1_manifest_ledger_authority_result(
                    "d1.migration_ledger_authority_unreadable",
                    "could not read the migration-ledger schema authority from D1",
                    "Reconcile the exact migration-ledger schema and primary readback before applying migration SQL.",
                )
            })?;
        parse_d1_migration_ledger_authority(&value, migrations_table)
    };
    let first = read_once().await?;
    // Once a first primary authority fact has been observed, a malformed or
    // contradictory second response is instability, not permission to retain
    // the first fact. This deliberately makes valid-first/invalid-second
    // drift observable at every apply/release boundary.
    let second = match read_once().await {
        Ok(second) => second,
        Err(_) => {
            return Err(d1_manifest_ledger_authority_result(
                "d1.migration_ledger_authority_unstable",
                "two primary migration-ledger authority readbacks disagreed or the second could not prove the same authority",
                "Reconcile concurrent or external ledger changes before applying migration SQL.",
            ));
        }
    };
    if first != second {
        return Err(d1_manifest_ledger_authority_result(
            "d1.migration_ledger_authority_unstable",
            "two primary migration-ledger authority readbacks disagreed",
            "Reconcile concurrent or external ledger changes before applying migration SQL.",
        ));
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
        "error": {"code": "d1.migration_apply_outcome_unknown", "message": "provider response after a migration apply was ambiguous; no retry or later migration was attempted", "hint": "Reconcile provider evidence and the exact ledger before clearing the retained target lease.", "cause": d1_manifest_nonretryable_cause(error)},
    }))
}

/// A response loss after a non-idempotent write is never permission to retry.
/// If the local custody chain can no longer be revalidated, it is also not
/// truthful to claim that this invocation retained the target lease. Preserve
/// the historical identity for reconciliation, but make no assertion that an
/// active local blocker still exists: absence is not a safe replay signal.
pub(crate) fn d1_manifest_reconciliation_custody_lost_result(
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
        "lease_retained": Value::Null,
        "custody_status": "lost_or_unverifiable_after_ambiguous_apply",
        "prior_lease_identity": lease.identity,
        "operator_handoff": "Do not replay this migration or infer safety from absent local lease evidence. Reconcile the named provider outcome and local custody through the governed recovery path before any subsequent apply.",
        "error": {
            "code": "d1.migration_apply_outcome_unknown_custody_lost",
            "message": "provider response after a migration apply was ambiguous and local target custody could not be revalidated; no retry or later migration was attempted",
            "hint": "Reconcile provider evidence first. Local lease absence is not authority to replay this migration.",
            "cause": d1_manifest_nonretryable_cause(error),
        },
    }))
}

/// A provider result can be diagnostically useful while still being unsafe to
/// expose verbatim at this boundary. In particular, a retryable HTTP response
/// after a non-idempotent write must not leak an instruction that contradicts
/// the manifest state machine's reconciliation-only rule.
fn d1_manifest_nonretryable_cause(error: Value) -> Value {
    let mut cause = Map::new();
    let detail = error.get("detail").and_then(Value::as_object);
    let kind = error.get("kind").and_then(Value::as_str).filter(|value| {
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    });

    if let Some(kind) = kind {
        cause.insert("kind".to_string(), Value::String(kind.to_string()));
    }
    if let Some(code) = detail
        .and_then(|detail| detail.get("code"))
        .or_else(|| error.get("code"))
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
                })
        })
    {
        cause.insert("code".to_string(), Value::String(code.to_string()));
    }
    if let Some(status) = detail
        .and_then(|detail| detail.get("status"))
        .or_else(|| error.get("status"))
        .and_then(Value::as_u64)
        .filter(|status| (100..=599).contains(status))
    {
        cause.insert("status".to_string(), json!(status));
    }
    if let Some(correlation_id) = detail
        .and_then(|detail| detail.get("correlation_id"))
        .or_else(|| error.get("correlation_id"))
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 256
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
        })
    {
        cause.insert(
            "correlation_id".to_string(),
            Value::String(correlation_id.to_string()),
        );
    }
    if kind == Some("provider_result") {
        if let Some(classification) = detail
            .and_then(|detail| detail.get("classification"))
            .and_then(Value::as_str)
            .and_then(d1_manifest_write_result_classification)
        {
            cause.insert(
                "classification".to_string(),
                Value::String(classification.to_string()),
            );
        }
    }
    cause.insert("retryable".to_string(), Value::Bool(false));
    cause.insert(
        "operator_guidance".to_string(),
        Value::String("reconciliation_only".to_string()),
    );
    Value::Object(cause)
}

/// Only classifications produced by `validate_d1_manifest_write_result` may
/// cross the provider-result boundary. This keeps the diagnostic finite while
/// preventing arbitrary nested provider detail from becoming operator guidance.
fn d1_manifest_write_result_classification(value: &str) -> Option<&'static str> {
    match value {
        "missing_or_non_array_result" => Some("missing_or_non_array_result"),
        "empty_result_set_sequence" => Some("empty_result_set_sequence"),
        "malformed_result_set" => Some("malformed_result_set"),
        "inner_statement_failure_or_missing_success" => {
            Some("inner_statement_failure_or_missing_success")
        }
        "inner_statement_error" => Some("inner_statement_error"),
        "malformed_inner_errors" => Some("malformed_inner_errors"),
        "missing_or_malformed_inner_results" => Some("missing_or_malformed_inner_results"),
        "missing_or_malformed_write_metadata" => Some("missing_or_malformed_write_metadata"),
        "write_not_served_by_primary" => Some("write_not_served_by_primary"),
        "write_did_not_acknowledge_database_change" => {
            Some("write_did_not_acknowledge_database_change")
        }
        "write_metadata_contradictory" => Some("write_metadata_contradictory"),
        "write_metadata_overflow" => Some("write_metadata_overflow"),
        "write_metadata_did_not_prove_mutation" => Some("write_metadata_did_not_prove_mutation"),
        _ => None,
    }
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
