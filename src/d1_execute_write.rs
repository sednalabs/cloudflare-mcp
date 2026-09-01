//! Side-effect-free exact-byte planning and DML acknowledgement classification.
//!
//! This module deliberately owns no provider client, tool route, custody, or
//! audit behavior. It also does not reuse migration-result semantics: an
//! `UPDATE` or `DELETE` that matches no row is a valid terminal DML result.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) const D1_EXECUTE_WRITE_OPERATION: &str = "d1_execute_write";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum D1WriteStatementKind {
    Insert,
    Update,
    Delete,
    Replace,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1ExecuteWritePlan {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) account_id: String,
    pub(crate) database_id: String,
    pub(crate) target_key_sha256: String,
    pub(crate) execution_session_sha256: String,
    pub(crate) statement_kind: D1WriteStatementKind,
    pub(crate) sql_sha256: String,
    pub(crate) sql_size_bytes: usize,
    pub(crate) params_sha256: String,
    pub(crate) params_size_bytes: usize,
    pub(crate) max_rows: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1ExecuteWriteOutcome {
    pub(crate) statement_kind: D1WriteStatementKind,
    pub(crate) changed_db: bool,
    pub(crate) changes: u64,
    pub(crate) rows_written: u64,
    pub(crate) zero_change: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1WriteResultClassification {
    MissingOrNonArrayResult,
    UnexpectedResultSetCount,
    MalformedResultSet,
    InnerStatementFailureOrMissingSuccess,
    InnerStatementError,
    MalformedInnerErrors,
    MissingOrMalformedInnerResults,
    MissingOrMalformedWriteMetadata,
    WriteNotServedByPrimary,
    WriteMetadataContradictory,
    WriteMetadataDidNotProveMutation,
    ZeroChangeNotTerminalForStatementKind,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1WriteResultError {
    pub(crate) code: &'static str,
    pub(crate) classification: D1WriteResultClassification,
    pub(crate) message: &'static str,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_d1_execute_write_plan(
    account_id: &str,
    database_id: &str,
    target_key_sha256: &str,
    execution_session_sha256: &str,
    statement_kind: D1WriteStatementKind,
    sql: &str,
    params: &[Value],
    max_rows: usize,
) -> (D1ExecuteWritePlan, String) {
    let params_bytes = serde_json::to_vec(params).expect("serializing JSON values cannot fail");
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
    let plan_bytes = serde_json::to_vec(&plan).expect("serializing the D1 write plan cannot fail");
    let plan_sha256 = sha256_bytes_hex(&plan_bytes);
    (plan, plan_sha256)
}

pub(crate) fn classify_d1_execute_write_result(
    statement_kind: D1WriteStatementKind,
    value: &Value,
) -> Result<D1ExecuteWriteOutcome, D1WriteResultError> {
    let result_sets = value.as_array().ok_or_else(|| {
        ambiguous(
            D1WriteResultClassification::MissingOrNonArrayResult,
            "provider response did not contain the D1 result-set array",
        )
    })?;
    let [result_set] = result_sets.as_slice() else {
        return Err(ambiguous(
            D1WriteResultClassification::UnexpectedResultSetCount,
            "one DML statement must return exactly one D1 result set",
        ));
    };
    let result_set = result_set.as_object().ok_or_else(|| {
        ambiguous(
            D1WriteResultClassification::MalformedResultSet,
            "provider DML result set was not an object",
        )
    })?;
    if result_set.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(ambiguous(
            D1WriteResultClassification::InnerStatementFailureOrMissingSuccess,
            "provider response did not prove a successful inner D1 statement",
        ));
    }
    match result_set.get("errors") {
        None => {}
        Some(Value::Array(errors)) if errors.is_empty() => {}
        Some(Value::Array(_)) => {
            return Err(ambiguous(
                D1WriteResultClassification::InnerStatementError,
                "provider DML result contained an inner statement error",
            ));
        }
        _ => {
            return Err(ambiguous(
                D1WriteResultClassification::MalformedInnerErrors,
                "provider DML result contained malformed inner errors",
            ));
        }
    }
    if !matches!(result_set.get("results"), Some(Value::Array(_))) {
        return Err(ambiguous(
            D1WriteResultClassification::MissingOrMalformedInnerResults,
            "provider DML result did not contain an inner results array",
        ));
    }
    let meta = result_set
        .get("meta")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ambiguous(
                D1WriteResultClassification::MissingOrMalformedWriteMetadata,
                "provider DML result did not contain exact mutation metadata",
            )
        })?;
    if meta.get("served_by_primary").and_then(Value::as_bool) != Some(true) {
        return Err(ambiguous(
            D1WriteResultClassification::WriteNotServedByPrimary,
            "provider DML result did not prove primary service",
        ));
    }
    let changed_db = meta
        .get("changed_db")
        .and_then(Value::as_bool)
        .ok_or_else(|| malformed_write_metadata("changed_db must be boolean"))?;
    let changes = meta
        .get("changes")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed_write_metadata("changes must be a non-negative u64 integer"))?;
    let rows_written = meta
        .get("rows_written")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            malformed_write_metadata("rows_written must be a non-negative u64 integer")
        })?;

    if !changed_db && (changes != 0 || rows_written != 0) {
        return Err(ambiguous(
            D1WriteResultClassification::WriteMetadataContradictory,
            "changed_db=false contradicted nonzero mutation counts",
        ));
    }
    if changed_db && (changes == 0 || rows_written == 0) {
        return Err(ambiguous(
            D1WriteResultClassification::WriteMetadataDidNotProveMutation,
            "changed_db=true did not carry positive mutation counts",
        ));
    }
    let zero_change = !changed_db;
    if zero_change
        && !matches!(
            statement_kind,
            D1WriteStatementKind::Update | D1WriteStatementKind::Delete
        )
    {
        return Err(ambiguous(
            D1WriteResultClassification::ZeroChangeNotTerminalForStatementKind,
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

fn malformed_write_metadata(message: &'static str) -> D1WriteResultError {
    ambiguous(
        D1WriteResultClassification::MissingOrMalformedWriteMetadata,
        message,
    )
}

fn ambiguous(
    classification: D1WriteResultClassification,
    message: &'static str,
) -> D1WriteResultError {
    D1WriteResultError {
        code: "d1.execute_write_result_ambiguous",
        classification,
        message,
    }
}

fn sha256_bytes_hex(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        D1WriteResultClassification, D1WriteStatementKind, classify_d1_execute_write_result,
        derive_d1_execute_write_plan,
    };

    fn result(changed_db: bool, changes: u64, rows_written: u64) -> Value {
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

    fn classification(value: &Value) -> D1WriteResultClassification {
        classify_d1_execute_write_result(D1WriteStatementKind::Update, value)
            .expect_err("fixture must be rejected")
            .classification
    }

    #[test]
    fn plan_binds_every_exact_execution_input() {
        let baseline = |account_id: &str,
                        database_id: &str,
                        target_key_sha256: &str,
                        execution_session_sha256: &str,
                        statement_kind: D1WriteStatementKind,
                        sql: &str,
                        params: &[Value],
                        max_rows: usize| {
            derive_d1_execute_write_plan(
                account_id,
                database_id,
                target_key_sha256,
                execution_session_sha256,
                statement_kind,
                sql,
                params,
                max_rows,
            )
            .1
        };
        let baseline_hash = baseline(
            "acct-1",
            "db-1",
            &"a".repeat(64),
            &"b".repeat(64),
            D1WriteStatementKind::Update,
            "  UPDATE sample SET flag = ?  ",
            &[json!(1)],
            100,
        );
        let variants = [
            baseline(
                "acct-2",
                "db-1",
                &"a".repeat(64),
                &"b".repeat(64),
                D1WriteStatementKind::Update,
                "  UPDATE sample SET flag = ?  ",
                &[json!(1)],
                100,
            ),
            baseline(
                "acct-1",
                "db-2",
                &"a".repeat(64),
                &"b".repeat(64),
                D1WriteStatementKind::Update,
                "  UPDATE sample SET flag = ?  ",
                &[json!(1)],
                100,
            ),
            baseline(
                "acct-1",
                "db-1",
                &"c".repeat(64),
                &"b".repeat(64),
                D1WriteStatementKind::Update,
                "  UPDATE sample SET flag = ?  ",
                &[json!(1)],
                100,
            ),
            baseline(
                "acct-1",
                "db-1",
                &"a".repeat(64),
                &"d".repeat(64),
                D1WriteStatementKind::Update,
                "  UPDATE sample SET flag = ?  ",
                &[json!(1)],
                100,
            ),
            baseline(
                "acct-1",
                "db-1",
                &"a".repeat(64),
                &"b".repeat(64),
                D1WriteStatementKind::Delete,
                "  UPDATE sample SET flag = ?  ",
                &[json!(1)],
                100,
            ),
            baseline(
                "acct-1",
                "db-1",
                &"a".repeat(64),
                &"b".repeat(64),
                D1WriteStatementKind::Update,
                "UPDATE sample SET flag = ?",
                &[json!(1)],
                100,
            ),
            baseline(
                "acct-1",
                "db-1",
                &"a".repeat(64),
                &"b".repeat(64),
                D1WriteStatementKind::Update,
                "  UPDATE sample SET flag = ?  ",
                &[json!(2)],
                100,
            ),
            baseline(
                "acct-1",
                "db-1",
                &"a".repeat(64),
                &"b".repeat(64),
                D1WriteStatementKind::Update,
                "  UPDATE sample SET flag = ?  ",
                &[json!(1)],
                101,
            ),
        ];
        assert!(variants.iter().all(|variant| variant != &baseline_hash));
    }

    #[test]
    fn update_and_delete_zero_change_are_terminal() {
        for statement_kind in [D1WriteStatementKind::Update, D1WriteStatementKind::Delete] {
            let outcome = classify_d1_execute_write_result(statement_kind, &result(false, 0, 0))
                .expect("zero-change update/delete is terminal");
            assert!(!outcome.changed_db);
            assert!(outcome.zero_change);
            assert_eq!(outcome.changes, 0);
            assert_eq!(outcome.rows_written, 0);
        }
    }

    #[test]
    fn insert_and_replace_zero_change_are_rejected() {
        for statement_kind in [D1WriteStatementKind::Insert, D1WriteStatementKind::Replace] {
            let error = classify_d1_execute_write_result(statement_kind, &result(false, 0, 0))
                .expect_err("zero-change insert/replace is ambiguous");
            assert_eq!(
                error.classification,
                D1WriteResultClassification::ZeroChangeNotTerminalForStatementKind
            );
        }
    }

    #[test]
    fn positive_mutation_is_terminal_for_every_dml_kind() {
        for statement_kind in [
            D1WriteStatementKind::Insert,
            D1WriteStatementKind::Update,
            D1WriteStatementKind::Delete,
            D1WriteStatementKind::Replace,
        ] {
            let outcome = classify_d1_execute_write_result(statement_kind, &result(true, 2, 1))
                .expect("positive mutation is terminal");
            assert!(outcome.changed_db);
            assert!(!outcome.zero_change);
            assert_eq!(outcome.changes, 2);
            assert_eq!(outcome.rows_written, 1);
        }
    }

    #[test]
    fn malformed_response_shapes_have_closed_aggregate_classifications() {
        let cases = [
            (
                Value::Null,
                D1WriteResultClassification::MissingOrNonArrayResult,
            ),
            (
                json!([]),
                D1WriteResultClassification::UnexpectedResultSetCount,
            ),
            (
                json!([{}, {}]),
                D1WriteResultClassification::UnexpectedResultSetCount,
            ),
            (
                json!([null]),
                D1WriteResultClassification::MalformedResultSet,
            ),
            (
                json!([{"success": false}]),
                D1WriteResultClassification::InnerStatementFailureOrMissingSuccess,
            ),
            (
                json!([{"success": true, "errors": ["private provider text"]}]),
                D1WriteResultClassification::InnerStatementError,
            ),
            (
                json!([{"success": true, "errors": "bad"}]),
                D1WriteResultClassification::MalformedInnerErrors,
            ),
            (
                json!([{"success": true, "errors": [], "results": null}]),
                D1WriteResultClassification::MissingOrMalformedInnerResults,
            ),
            (
                json!([{"success": true, "errors": [], "results": [], "meta": null}]),
                D1WriteResultClassification::MissingOrMalformedWriteMetadata,
            ),
        ];
        for (value, expected) in cases {
            let error = classify_d1_execute_write_result(D1WriteStatementKind::Update, &value)
                .expect_err("malformed response must be rejected");
            assert_eq!(error.classification, expected);
            let serialized = serde_json::to_string(&error).expect("serialize aggregate-safe error");
            assert!(!serialized.contains("private provider text"));
        }
    }

    #[test]
    fn primary_and_typed_integer_bounds_are_required() {
        let mut non_primary = result(true, 1, 1);
        non_primary[0]["meta"]["served_by_primary"] = json!(false);
        assert_eq!(
            classification(&non_primary),
            D1WriteResultClassification::WriteNotServedByPrimary
        );

        let mut missing_primary = result(true, 1, 1);
        missing_primary[0]["meta"]
            .as_object_mut()
            .expect("meta")
            .remove("served_by_primary");
        assert_eq!(
            classification(&missing_primary),
            D1WriteResultClassification::WriteNotServedByPrimary
        );
        let mut malformed_primary = result(true, 1, 1);
        malformed_primary[0]["meta"]["served_by_primary"] = json!("true");
        assert_eq!(
            classification(&malformed_primary),
            D1WriteResultClassification::WriteNotServedByPrimary
        );

        for malformed in [Value::Null, json!("true"), json!(1)] {
            let mut value = result(true, 1, 1);
            value[0]["meta"]["changed_db"] = malformed;
            assert_eq!(
                classification(&value),
                D1WriteResultClassification::MissingOrMalformedWriteMetadata
            );
        }

        for field in ["changes", "rows_written"] {
            let above_u64 = serde_json::from_str::<Value>("18446744073709551616")
                .expect("JSON number beyond u64 remains a typed JSON number");
            for malformed in [json!(-1), json!(1.5), json!("1"), Value::Null, above_u64] {
                let mut value = result(true, 1, 1);
                value[0]["meta"][field] = malformed;
                assert_eq!(
                    classification(&value),
                    D1WriteResultClassification::MissingOrMalformedWriteMetadata
                );
            }
        }

        let maximum = result(true, u64::MAX, u64::MAX);
        let outcome = classify_d1_execute_write_result(D1WriteStatementKind::Update, &maximum)
            .expect("u64 bounds are typed without lossy conversion");
        assert_eq!(outcome.changes, u64::MAX);
        assert_eq!(outcome.rows_written, u64::MAX);
    }

    #[test]
    fn contradictory_metadata_is_rejected_deterministically() {
        for value in [
            result(false, 1, 0),
            result(false, 0, 1),
            result(false, 1, 1),
        ] {
            assert_eq!(
                classification(&value),
                D1WriteResultClassification::WriteMetadataContradictory
            );
        }
        for value in [result(true, 0, 1), result(true, 1, 0), result(true, 0, 0)] {
            assert_eq!(
                classification(&value),
                D1WriteResultClassification::WriteMetadataDidNotProveMutation
            );
        }
    }
}
