//! Exact-byte planning and DML-specific provider acknowledgement rules for
//! `d1_execute_write`.
//!
//! This module deliberately does not reuse migration-result semantics: an
//! UPDATE or DELETE that matches no row is a valid terminal DML result.

use serde::Serialize;
use serde_json::{Value, json};

use crate::tools::sha256_bytes_hex;

pub(crate) const D1_EXECUTE_WRITE_OPERATION: &str = "d1_execute_write";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1ExecuteWritePlan {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) account_id: String,
    pub(crate) database_id: String,
    pub(crate) target_key_sha256: String,
    pub(crate) execution_session_sha256: String,
    pub(crate) statement_kind: &'static str,
    pub(crate) sql_sha256: String,
    pub(crate) sql_size_bytes: usize,
    pub(crate) params_sha256: String,
    pub(crate) params_size_bytes: usize,
    pub(crate) max_rows: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1ExecuteWriteOutcome {
    pub(crate) statement_kind: &'static str,
    pub(crate) changed_db: bool,
    pub(crate) changes: u64,
    pub(crate) rows_written: u64,
    pub(crate) zero_change: bool,
}

pub(crate) fn derive_d1_execute_write_plan(
    account_id: &str,
    database_id: &str,
    target_key_sha256: &str,
    execution_session_sha256: &str,
    statement_kind: &'static str,
    sql: &str,
    params: &[Value],
    max_rows: usize,
) -> (D1ExecuteWritePlan, String) {
    let params_bytes =
        serde_json::to_vec(params).expect("serializing D1 write parameters is infallible");
    let plan = D1ExecuteWritePlan {
        version: 2,
        operation: D1_EXECUTE_WRITE_OPERATION,
        account_id: account_id.to_string(),
        database_id: database_id.to_string(),
        target_key_sha256: target_key_sha256.to_string(),
        execution_session_sha256: execution_session_sha256.to_string(),
        statement_kind,
        sql_sha256: sha256_bytes_hex(sql.as_bytes()),
        sql_size_bytes: sql.len(),
        params_sha256: sha256_bytes_hex(&params_bytes),
        params_size_bytes: params_bytes.len(),
        max_rows,
    };
    let plan_bytes = serde_json::to_vec(&plan).expect("serializing D1 write plan is infallible");
    let plan_sha256 = sha256_bytes_hex(&plan_bytes);
    (plan, plan_sha256)
}

pub(crate) fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_d1_execute_write_result(
    statement_kind: &'static str,
    value: &Value,
) -> Result<D1ExecuteWriteOutcome, Value> {
    let result_sets = value.as_array().ok_or_else(|| {
        ambiguous(
            "missing_or_non_array_result",
            "provider response did not contain the D1 result-set array",
        )
    })?;
    let [result_set] = result_sets.as_slice() else {
        return Err(ambiguous(
            "unexpected_result_set_count",
            "one DML statement must return exactly one D1 result set",
        ));
    };
    let result_set = result_set.as_object().ok_or_else(|| {
        ambiguous(
            "malformed_result_set",
            "provider DML result set was not an object",
        )
    })?;
    if result_set.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(ambiguous(
            "inner_statement_failure_or_missing_success",
            "provider response did not prove a successful inner D1 statement",
        ));
    }
    match result_set.get("errors") {
        None => {}
        Some(Value::Array(errors)) if errors.is_empty() => {}
        Some(Value::Array(_)) => {
            return Err(ambiguous(
                "inner_statement_error",
                "provider DML result contained an inner statement error",
            ));
        }
        _ => {
            return Err(ambiguous(
                "malformed_inner_errors",
                "provider DML result contained malformed inner errors",
            ));
        }
    }
    if !matches!(result_set.get("results"), Some(Value::Array(_))) {
        return Err(ambiguous(
            "missing_or_malformed_inner_results",
            "provider DML result did not contain an inner results array",
        ));
    }
    let meta = result_set
        .get("meta")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ambiguous(
                "missing_or_malformed_write_metadata",
                "provider DML result did not contain exact mutation metadata",
            )
        })?;
    if meta.get("served_by_primary").and_then(Value::as_bool) != Some(true) {
        return Err(ambiguous(
            "write_not_served_by_primary",
            "provider DML result did not prove primary service",
        ));
    }
    let changed_db = meta
        .get("changed_db")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            ambiguous(
                "missing_or_malformed_write_metadata",
                "provider DML result did not contain boolean changed_db",
            )
        })?;
    let changes = meta.get("changes").and_then(Value::as_u64).ok_or_else(|| {
        ambiguous(
            "missing_or_malformed_write_metadata",
            "provider DML result did not contain non-negative integer changes",
        )
    })?;
    let rows_written = meta
        .get("rows_written")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ambiguous(
                "missing_or_malformed_write_metadata",
                "provider DML result did not contain non-negative integer rows_written",
            )
        })?;

    if !changed_db && (changes != 0 || rows_written != 0) {
        return Err(ambiguous(
            "write_metadata_contradictory",
            "changed_db=false contradicted nonzero mutation counts",
        ));
    }
    if changed_db && (changes == 0 || rows_written == 0) {
        return Err(ambiguous(
            "write_metadata_did_not_prove_mutation",
            "changed_db=true did not carry positive mutation counts",
        ));
    }
    let zero_change = !changed_db;
    if zero_change && !matches!(statement_kind, "UPDATE" | "DELETE") {
        return Err(ambiguous(
            "zero_change_not_terminal_for_statement_kind",
            "only UPDATE or DELETE may terminate successfully with zero changed rows",
        ));
    }
    Ok(D1ExecuteWriteOutcome {
        statement_kind,
        changed_db,
        changes,
        rows_written,
        zero_change,
    })
}

fn ambiguous(classification: &'static str, message: &'static str) -> Value {
    json!({
        "code": "d1.execute_write_result_ambiguous",
        "classification": classification,
        "message": message,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{derive_d1_execute_write_plan, validate_d1_execute_write_result};

    fn result(changed_db: bool, changes: u64, rows_written: u64) -> serde_json::Value {
        json!([{
            "success": true,
            "errors": [],
            "results": [],
            "meta": {
                "served_by_primary": true,
                "changed_db": changed_db,
                "changes": changes,
                "rows_written": rows_written,
            }
        }])
    }

    #[test]
    fn plan_hashes_the_exact_sql_bytes_that_will_be_dispatched() {
        let (spaced, spaced_hash) = derive_d1_execute_write_plan(
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            &"a".repeat(64),
            &"b".repeat(64),
            "UPDATE",
            "  UPDATE sample SET flag = 1  ",
            &[],
            100,
        );
        let (trimmed, trimmed_hash) = derive_d1_execute_write_plan(
            "acct-1",
            "123e4567-e89b-42d3-a456-426614174000",
            &"a".repeat(64),
            &"b".repeat(64),
            "UPDATE",
            "UPDATE sample SET flag = 1",
            &[],
            100,
        );
        assert_ne!(spaced.sql_sha256, trimmed.sql_sha256);
        assert_ne!(spaced.sql_size_bytes, trimmed.sql_size_bytes);
        assert_ne!(spaced_hash, trimmed_hash);
    }

    #[test]
    fn update_and_delete_zero_change_are_terminal_but_insert_is_not() {
        for statement_kind in ["UPDATE", "DELETE"] {
            let outcome = validate_d1_execute_write_result(statement_kind, &result(false, 0, 0))
                .expect("zero-change update/delete is a valid DML acknowledgement");
            assert!(outcome.zero_change);
        }
        let insert = validate_d1_execute_write_result("INSERT", &result(false, 0, 0))
            .expect_err("zero-change insert lacks a terminal acknowledgement");
        assert_eq!(
            insert["classification"],
            "zero_change_not_terminal_for_statement_kind"
        );
    }

    #[test]
    fn positive_mutation_and_contradictory_metadata_are_distinct() {
        let outcome = validate_d1_execute_write_result("INSERT", &result(true, 1, 1))
            .expect("positive mutation");
        assert_eq!(outcome.changes, 1);
        assert!(!outcome.zero_change);
        for malformed in [result(false, 1, 1), result(true, 0, 0)] {
            assert!(validate_d1_execute_write_result("UPDATE", &malformed).is_err());
        }
    }
}
