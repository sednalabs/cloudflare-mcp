//! Provider-resident admission authority for one immutable D1 import session.
//!
//! This module intentionally does not implement SQL-file import transport or
//! terminal recovery. It owns only the admission row and the exact fresh
//! readback that a future import coordinator must perform while holding the
//! shared account/database target lease immediately before initialization.

use rmcp::model::CallToolResult;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::cloudflare::CloudflareClient;
use crate::d1_migration_lease::{
    D1MigrationLease, D1TargetLeaseAcquisition, D1TargetLeaseBinding, D1TargetWriter,
    acquire_d1_target_lease, d1_target_key_sha256,
};
use crate::d1_migration_manifest::validate_d1_manifest_write_result;
use crate::tools::{invalid_argument_result, sha256_hex};

pub(crate) const D1_IMPORT_ADMISSION_TABLE: &str = "mcp_d1_import_attempt_admissions";

pub(crate) fn sql_mentions_import_admission(sql: &str) -> bool {
    let lowered = strip_sql_literals_and_comments(sql).to_ascii_lowercase();
    lowered
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .any(|token| token == D1_IMPORT_ADMISSION_TABLE)
}

fn strip_sql_literals_and_comments(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\'' {
            out.push(' ');
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\'' {
                    index += 1;
                    if index < bytes.len() && bytes[index] == b'\'' {
                        index += 1;
                        continue;
                    }
                    break;
                }
                index += 1;
            }
        } else if bytes[index..].starts_with(b"--") {
            out.push(' ');
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            out.push(' ');
            index += 2;
            while index + 1 < bytes.len() && !bytes[index..].starts_with(b"*/") {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
        } else {
            out.push(bytes[index] as char);
            index += 1;
        }
    }
    out
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct D1AdmitImportAttemptArgs {
    #[serde(default)]
    pub(crate) account_id: Option<String>,
    pub(crate) database_id: String,
    pub(crate) content_plan_sha256: String,
    pub(crate) execution_session_sha256: String,
    #[serde(default)]
    pub(crate) dry_run: bool,
    #[serde(default)]
    pub(crate) approved_request_sha256: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct D1ReadImportAdmissionArgs {
    #[serde(default)]
    pub(crate) account_id: Option<String>,
    pub(crate) database_id: String,
    pub(crate) request_sha256: String,
    pub(crate) content_plan_sha256: String,
    pub(crate) execution_session_sha256: String,
}

#[derive(Debug, Clone)]
pub(crate) struct D1ImportAdmissionBinding {
    request_sha256: String,
    target_key_sha256: String,
    content_plan_sha256: String,
    execution_session_sha256: String,
}

impl D1ImportAdmissionBinding {
    pub(crate) fn new(
        account_id: &str,
        database_id: &str,
        content_plan_sha256: &str,
        execution_session_sha256: &str,
    ) -> Self {
        Self {
            request_sha256: import_admission_request_sha256(
                account_id,
                database_id,
                content_plan_sha256,
                execution_session_sha256,
            ),
            target_key_sha256: d1_target_key_sha256(account_id, database_id),
            content_plan_sha256: content_plan_sha256.to_string(),
            execution_session_sha256: execution_session_sha256.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionRead {
    Exact,
    Absent,
    Conflict,
    Unavailable,
}

pub(crate) fn import_admission_request_sha256(
    account_id: &str,
    database_id: &str,
    content_plan_sha256: &str,
    execution_session_sha256: &str,
) -> String {
    sha256_hex(
        &serde_json::to_string(&json!({
            "contract": "d1-import-provider-admission-v2",
            "target_key_sha256": d1_target_key_sha256(account_id, database_id),
            "content_plan_sha256": content_plan_sha256,
            "execution_session_sha256": execution_session_sha256,
        }))
        .expect("serializing import admission request is infallible"),
    )
}

pub(crate) async fn admit_import_attempt(
    client: &CloudflareClient,
    account_id: &str,
    args: &D1AdmitImportAttemptArgs,
) -> CallToolResult {
    if let Err(result) = require_sha("content_plan_sha256", &args.content_plan_sha256)
        .and_then(|_| require_sha("execution_session_sha256", &args.execution_session_sha256))
    {
        return result;
    }
    let binding = D1ImportAdmissionBinding::new(
        account_id,
        &args.database_id,
        &args.content_plan_sha256,
        &args.execution_session_sha256,
    );
    let base = json!({
        "operation": "d1_admit_import_attempt",
        "target_key_sha256": binding.target_key_sha256,
        "request_sha256": binding.request_sha256,
        "content_plan_sha256": binding.content_plan_sha256,
        "execution_session_sha256": binding.execution_session_sha256,
    });
    if args.dry_run {
        return CallToolResult::structured(json!({
            "ok": true,
            "status": "previewed",
            "dry_run": true,
            "provider_calls": 0,
            "provider_mutations": 0,
            "plan": base,
        }));
    }
    if args.approved_request_sha256.as_deref() != Some(binding.request_sha256.as_str()) {
        return invalid_argument_result(
            "d1.import_admission_approval_mismatch",
            "live import admission requires the exact request_sha256 returned by dry run",
            "Repeat dry run and approve its exact immutable request digest.",
        );
    }
    let mut lease = match acquire_d1_target_lease(
        account_id,
        &args.database_id,
        args.approved_request_sha256.as_deref(),
        D1TargetLeaseBinding {
            writer: D1TargetWriter::ImportAdmission,
            execution_session_sha256: &binding.execution_session_sha256,
            content_plan_sha256: &binding.content_plan_sha256,
        },
    ) {
        Ok(D1TargetLeaseAcquisition::Acquired(lease)) => lease,
        Ok(D1TargetLeaseAcquisition::ExactTerminalReplay(identity)) => {
            return match read_admission(client, account_id, &args.database_id, &binding).await {
                AdmissionRead::Exact => CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "d1_admit_import_attempt",
                    "status": "exact_terminal_replay",
                    "provider_calls": 1,
                    "provider_mutations": 0,
                    "plan": base,
                    "lease": identity,
                })),
                _ => admission_error(
                    "d1.import_admission_terminal_conflict",
                    "terminal local admission evidence is not matched by exact provider readback",
                    true,
                ),
            };
        }
        Err(result) => return result,
    };
    if let Err(result) = lease.revalidate() {
        return result;
    }
    match read_admission(client, account_id, &args.database_id, &binding).await {
        AdmissionRead::Exact => {
            if let Err(result) = lease.release() {
                return result;
            }
            return CallToolResult::structured(json!({
                "ok": true,
                "operation": "d1_admit_import_attempt",
                "status": "exact_provider_replay",
                "provider_calls": 1,
                "provider_mutations": 0,
                "plan": base,
                "lease": lease.identity,
            }));
        }
        AdmissionRead::Absent => {}
        AdmissionRead::Conflict => {
            if let Err(result) = lease.abort_before_dispatch() {
                return result;
            }
            return admission_error(
                "d1.import_admission_conflict",
                "provider admission authority contradicts this immutable session binding",
                false,
            );
        }
        AdmissionRead::Unavailable => {
            if let Err(result) = lease.abort_before_dispatch() {
                return result;
            }
            return admission_error(
                "d1.import_admission_read_unavailable",
                "provider admission authority could not be read exactly before mutation",
                false,
            );
        }
    }
    if let Err(result) = lease.revalidate() {
        return result;
    }
    let sql = format!(
        "INSERT INTO {D1_IMPORT_ADMISSION_TABLE} (request_sha256, target_key_sha256, content_plan_sha256, execution_session_sha256) VALUES (?, ?, ?, ?)"
    );
    let params = [
        json!(binding.request_sha256),
        json!(binding.target_key_sha256),
        json!(binding.content_plan_sha256),
        json!(binding.execution_session_sha256),
    ];
    match client
        .execute_d1_migration_manifest_write(account_id, &args.database_id, &sql, &params)
        .await
    {
        Ok(write) if validate_d1_manifest_write_result(&write.result).is_ok() => {
            finish_admission_readback(client, account_id, args, base, binding, lease, 3, 1).await
        }
        Ok(write) => {
            lease.retain();
            CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "d1_admit_import_attempt",
                "status": "reconciliation_required",
                "retry_decision": "do_not_retry_same_attempt",
                "lease_retained": true,
                "provider_calls": 2,
                "provider_mutations": 1,
                "provider_lifecycle": write.lifecycle,
                "lease": lease.identity,
                "plan": base,
                "error": {"code": "d1.import_admission_response_invalid", "message": "provider admission write response was not exact success evidence", "hint": "Reconcile the admission row under retained target custody before any import initialization."}
            }))
        }
        Err(error) if error.lifecycle.dispatch_stage == "pre_dispatch" => {
            if let Err(result) = lease.abort_before_dispatch() {
                return result;
            }
            CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "d1_admit_import_attempt",
                "status": "not_dispatched",
                "lease_retained": false,
                "provider_calls": 1,
                "provider_mutations": 0,
                "provider_lifecycle": error.lifecycle,
                "plan": base,
                "error": error.error,
            }))
        }
        Err(error) => match read_admission(client, account_id, &args.database_id, &binding).await {
            AdmissionRead::Exact => {
                if let Err(result) = lease.release() {
                    return result;
                }
                CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "d1_admit_import_attempt",
                    "status": "provider_outcome_reconciled",
                    "provider_calls": 3,
                    "provider_mutations": 1,
                    "plan": base,
                    "lease": lease.identity,
                }))
            }
            _ => {
                lease.retain();
                CallToolResult::structured_error(json!({
                    "ok": false,
                    "operation": "d1_admit_import_attempt",
                    "status": "reconciliation_required",
                    "retry_decision": "do_not_retry_same_attempt",
                    "lease_retained": true,
                    "provider_calls": 3,
                    "provider_mutations": 1,
                    "provider_lifecycle": error.lifecycle,
                    "lease": lease.identity,
                    "plan": base,
                    "error": error.error,
                }))
            }
        },
    }
}

async fn finish_admission_readback(
    client: &CloudflareClient,
    account_id: &str,
    args: &D1AdmitImportAttemptArgs,
    base: Value,
    binding: D1ImportAdmissionBinding,
    mut lease: D1MigrationLease,
    provider_calls: usize,
    provider_mutations: usize,
) -> CallToolResult {
    match read_admission(client, account_id, &args.database_id, &binding).await {
        AdmissionRead::Exact => {
            if let Err(result) = lease.release() {
                return result;
            }
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "d1_admit_import_attempt",
                "status": "admitted",
                "provider_calls": provider_calls,
                "provider_mutations": provider_mutations,
                "plan": base,
                "lease": lease.identity,
            }))
        }
        _ => {
            lease.retain();
            admission_error(
                "d1.import_admission_readback_not_exact",
                "provider admission write lacks exact fresh readback",
                true,
            )
        }
    }
}

pub(crate) async fn read_import_admission(
    client: &CloudflareClient,
    account_id: &str,
    args: &D1ReadImportAdmissionArgs,
) -> CallToolResult {
    for (name, value) in [
        ("request_sha256", args.request_sha256.as_str()),
        ("content_plan_sha256", args.content_plan_sha256.as_str()),
        (
            "execution_session_sha256",
            args.execution_session_sha256.as_str(),
        ),
    ] {
        if let Err(result) = require_sha(name, value) {
            return result;
        }
    }
    let binding = D1ImportAdmissionBinding::new(
        account_id,
        &args.database_id,
        &args.content_plan_sha256,
        &args.execution_session_sha256,
    );
    if binding.request_sha256 != args.request_sha256 {
        return admission_error(
            "d1.import_admission_request_conflict",
            "request_sha256 does not bind this exact target, content plan, and execution session",
            false,
        );
    }
    match read_admission(client, account_id, &args.database_id, &binding).await {
        AdmissionRead::Exact => CallToolResult::structured(json!({
            "ok": true,
            "operation": "d1_read_import_admission",
            "status": "admitted_exact",
            "read_only": true,
            "provider_calls": 1,
            "provider_mutations": 0,
            "target_key_sha256": binding.target_key_sha256,
            "request_sha256": binding.request_sha256,
            "content_plan_sha256": binding.content_plan_sha256,
            "execution_session_sha256": binding.execution_session_sha256,
        })),
        AdmissionRead::Absent => admission_error(
            "d1.import_admission_absent",
            "exact provider admission is absent",
            false,
        ),
        AdmissionRead::Conflict => admission_error(
            "d1.import_admission_conflict",
            "provider admission row conflicts with the requested immutable binding",
            false,
        ),
        AdmissionRead::Unavailable => admission_error(
            "d1.import_admission_read_unavailable",
            "provider admission state could not be read exactly",
            false,
        ),
    }
}

/// Import execution must call this after acquiring the shared target lease and
/// immediately before its initialization request. No earlier admission read is
/// authority for initialization.
#[allow(dead_code)] // Consumed by the separately bounded import-transport slice.
pub(crate) async fn reread_import_admission_before_initialization(
    client: &CloudflareClient,
    account_id: &str,
    database_id: &str,
    binding: &D1ImportAdmissionBinding,
    lease: &D1MigrationLease,
) -> Result<(), CallToolResult> {
    lease.revalidate()?;
    let read = read_admission(client, account_id, database_id, binding).await;
    lease.revalidate()?;
    match read {
        AdmissionRead::Exact => Ok(()),
        AdmissionRead::Absent => Err(admission_error(
            "d1.import_admission_absent_before_initialization",
            "fresh provider admission is absent immediately before import initialization",
            true,
        )),
        AdmissionRead::Conflict => Err(admission_error(
            "d1.import_admission_conflict_before_initialization",
            "fresh provider admission contradicts the exact import session immediately before initialization",
            true,
        )),
        AdmissionRead::Unavailable => Err(admission_error(
            "d1.import_admission_unavailable_before_initialization",
            "fresh provider admission could not be proven immediately before initialization",
            true,
        )),
    }
}

async fn read_admission(
    client: &CloudflareClient,
    account_id: &str,
    database_id: &str,
    expected: &D1ImportAdmissionBinding,
) -> AdmissionRead {
    let sql = format!(
        "SELECT request_sha256, target_key_sha256, content_plan_sha256, execution_session_sha256 FROM {D1_IMPORT_ADMISSION_TABLE} WHERE request_sha256 = ?"
    );
    let value = match client
        .query_d1_migration_manifest(
            account_id,
            database_id,
            &sql,
            &[json!(expected.request_sha256)],
        )
        .await
    {
        Ok(value) => value,
        Err(_) => return AdmissionRead::Unavailable,
    };
    classify_admission_rows(&value, expected)
}

fn classify_admission_rows(value: &Value, expected: &D1ImportAdmissionBinding) -> AdmissionRead {
    let result_sets = match value.as_array() {
        Some(result_sets) if result_sets.len() == 1 => result_sets,
        _ => return AdmissionRead::Unavailable,
    };
    let result_set = match result_sets[0].as_object() {
        Some(result_set) => result_set,
        None => return AdmissionRead::Unavailable,
    };
    if result_set.get("success").and_then(Value::as_bool) != Some(true)
        || result_set
            .get("meta")
            .and_then(Value::as_object)
            .and_then(|meta| meta.get("served_by_primary"))
            .and_then(Value::as_bool)
            != Some(true)
        || result_set
            .get("errors")
            .is_some_and(|errors| !matches!(errors, Value::Array(values) if values.is_empty()))
    {
        return AdmissionRead::Unavailable;
    }
    let rows = match result_set.get("results").and_then(Value::as_array) {
        Some(rows) => rows,
        None => return AdmissionRead::Unavailable,
    };
    if rows.is_empty() {
        return AdmissionRead::Absent;
    }
    if rows.len() != 1 {
        return AdmissionRead::Conflict;
    }
    let row = match rows[0].as_object() {
        Some(row) if row.len() == 4 => row,
        _ => return AdmissionRead::Conflict,
    };
    let exact = row.get("request_sha256").and_then(Value::as_str)
        == Some(expected.request_sha256.as_str())
        && row.get("target_key_sha256").and_then(Value::as_str)
            == Some(expected.target_key_sha256.as_str())
        && row.get("content_plan_sha256").and_then(Value::as_str)
            == Some(expected.content_plan_sha256.as_str())
        && row.get("execution_session_sha256").and_then(Value::as_str)
            == Some(expected.execution_session_sha256.as_str());
    if exact {
        AdmissionRead::Exact
    } else {
        AdmissionRead::Conflict
    }
}

fn require_sha(name: &'static str, value: &str) -> Result<(), CallToolResult> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(invalid_argument_result(
            "d1.import_admission_digest_invalid",
            format!("{name} must be an exact lowercase SHA-256 digest"),
            "Use the exact digest from the immutable import plan.",
        ))
    }
}

fn admission_error(
    code: &'static str,
    message: &'static str,
    lease_retained: bool,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_import_admission",
        "status": if lease_retained { "reconciliation_required" } else { "denied" },
        "retry_decision": if lease_retained { "do_not_retry_same_attempt" } else { "correct_evidence_then_retry" },
        "lease_retained": lease_retained,
        "error": {
            "code": code,
            "message": message,
            "hint": "Do not initialize an import unless one fresh exact provider admission read succeeds while the shared target lease is held."
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> D1ImportAdmissionBinding {
        D1ImportAdmissionBinding {
            request_sha256: "a".repeat(64),
            target_key_sha256: "b".repeat(64),
            content_plan_sha256: "c".repeat(64),
            execution_session_sha256: "d".repeat(64),
        }
    }

    fn result(rows: Value) -> Value {
        json!([{
            "success": true,
            "errors": [],
            "meta": {"served_by_primary": true},
            "results": rows,
        }])
    }

    #[test]
    fn admission_row_matrix_is_fail_closed() {
        let expected = binding();
        assert_eq!(
            classify_admission_rows(&result(json!([])), &expected),
            AdmissionRead::Absent
        );
        assert_eq!(
            classify_admission_rows(
                &result(json!([{
                    "request_sha256": expected.request_sha256,
                    "target_key_sha256": expected.target_key_sha256,
                    "content_plan_sha256": expected.content_plan_sha256,
                    "execution_session_sha256": expected.execution_session_sha256,
                }])),
                &expected,
            ),
            AdmissionRead::Exact
        );
        let mut contradictory = result(json!([{
            "request_sha256": expected.request_sha256,
            "target_key_sha256": expected.target_key_sha256,
            "content_plan_sha256": expected.content_plan_sha256,
            "execution_session_sha256": expected.execution_session_sha256,
        }]));
        contradictory[0]["results"][0]["content_plan_sha256"] = json!("e".repeat(64));
        assert_eq!(
            classify_admission_rows(&contradictory, &expected),
            AdmissionRead::Conflict
        );
        assert_eq!(
            classify_admission_rows(&json!({"success": true}), &expected),
            AdmissionRead::Unavailable
        );
        assert_eq!(
            classify_admission_rows(&result(json!([null])), &expected,),
            AdmissionRead::Conflict
        );
    }

    #[test]
    fn admission_request_binds_target_content_and_session() {
        let first = import_admission_request_sha256(
            "account",
            "database",
            &"a".repeat(64),
            &"b".repeat(64),
        );
        assert_ne!(
            first,
            import_admission_request_sha256("account", "other", &"a".repeat(64), &"b".repeat(64))
        );
        assert_ne!(
            first,
            import_admission_request_sha256(
                "account",
                "database",
                &"c".repeat(64),
                &"b".repeat(64)
            )
        );
        assert_ne!(
            first,
            import_admission_request_sha256(
                "account",
                "database",
                &"a".repeat(64),
                &"d".repeat(64)
            )
        );
    }

    #[test]
    fn reserved_admission_relation_detection_ignores_literals_and_comments() {
        assert!(sql_mentions_import_admission(
            "UPDATE mcp_d1_import_attempt_admissions SET request_sha256 = 'a'"
        ));
        assert!(!sql_mentions_import_admission(
            "INSERT INTO notes VALUES ('mcp_d1_import_attempt_admissions') -- mcp_d1_import_attempt_admissions"
        ));
    }
}
