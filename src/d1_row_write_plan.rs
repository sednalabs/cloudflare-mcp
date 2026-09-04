//! Canonical, side-effect-free planning for the future guarded D1 row-write
//! adapter.
//!
//! This is deliberately not a tool contract and it has no provider, custody,
//! persistence, or admission capability.  The constructor is private to this
//! module: callers can only obtain a plan through the pure function below.
//! The existing D1 execute-write planner remains the canonical byte layout so
//! the staged adapter does not invent a second hashing scheme.

use serde_json::Value;

use crate::d1_execute_write::{
    D1ExecuteWritePlan, D1WriteStatementKind, derive_d1_execute_write_plan,
};
use crate::d1_target::D1TargetIdentity;

const D1_ROW_WRITE_PLAN_MAX_ROWS: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum D1RowWritePlanError {
    InvalidExecutionSessionIdentity,
    InvalidRowLimit,
}

/// A canonical intended row-write plan.  Raw SQL and parameter values are
/// intentionally not retained, and the fields are private so a caller cannot
/// deserialize or hand-construct a plan that becomes causal evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1RowWritePlan {
    inner: D1ExecuteWritePlan,
    plan_sha256: String,
}

impl D1RowWritePlan {
    pub(crate) fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }

    pub(crate) fn target_key_sha256(&self) -> &str {
        &self.inner.target_key_sha256
    }

    pub(crate) fn statement_kind(&self) -> D1WriteStatementKind {
        self.inner.statement_kind
    }
}

fn canonical_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Derive one immutable plan from the already-classified statement kind.
///
/// SQL classification remains owned by the existing pure D1 write classifier;
/// this function only adds the adapter's private plan boundary and verifies
/// the identity/row-limit inputs before reusing the current planner.
#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_d1_row_write_plan(
    target: &D1TargetIdentity,
    execution_session_sha256: &str,
    statement_kind: D1WriteStatementKind,
    sql: &str,
    params: &[Value],
    max_rows: usize,
) -> Result<D1RowWritePlan, D1RowWritePlanError> {
    if !canonical_hash(execution_session_sha256) {
        return Err(D1RowWritePlanError::InvalidExecutionSessionIdentity);
    }
    if !(1..=D1_ROW_WRITE_PLAN_MAX_ROWS).contains(&max_rows) {
        return Err(D1RowWritePlanError::InvalidRowLimit);
    }
    let (inner, plan_sha256) = derive_d1_execute_write_plan(
        &target.account_id,
        &target.database_id,
        &target.target_key_sha256(),
        execution_session_sha256,
        statement_kind,
        sql,
        params,
        max_rows,
    );
    Ok(D1RowWritePlan { inner, plan_sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::d1_target::normalize_d1_target;
    use serde_json::json;

    fn target() -> D1TargetIdentity {
        normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000")
            .expect("fixture target is canonical")
    }

    #[test]
    fn plan_is_derived_from_existing_exact_planner_without_retaining_raw_values() {
        let plan = derive_d1_row_write_plan(
            &target(),
            &"a".repeat(64),
            D1WriteStatementKind::Insert,
            "INSERT INTO t (id) VALUES (?)",
            &[json!("fixture")],
            100,
        )
        .expect("canonical plan");

        assert_eq!(plan.target_key_sha256().len(), 64);
        assert_eq!(plan.plan_sha256().len(), 64);
        assert_eq!(plan.statement_kind(), D1WriteStatementKind::Insert);
        let debug = format!("{plan:?}");
        assert!(!debug.contains("INSERT INTO"));
        assert!(!debug.contains("fixture"));
    }

    #[test]
    fn plan_changes_when_intended_mutation_changes() {
        let first = derive_d1_row_write_plan(
            &target(),
            &"a".repeat(64),
            D1WriteStatementKind::Update,
            "UPDATE t SET enabled = ?",
            &[json!(true)],
            100,
        )
        .expect("canonical plan");
        let second = derive_d1_row_write_plan(
            &target(),
            &"a".repeat(64),
            D1WriteStatementKind::Update,
            "UPDATE t SET enabled = ?",
            &[json!(false)],
            100,
        )
        .expect("canonical plan");
        assert_ne!(first.plan_sha256(), second.plan_sha256());
    }

    #[test]
    fn plan_rejects_noncanonical_session_or_row_limit() {
        assert_eq!(
            derive_d1_row_write_plan(
                &target(),
                "session",
                D1WriteStatementKind::Delete,
                "DELETE FROM t",
                &[],
                1,
            ),
            Err(D1RowWritePlanError::InvalidExecutionSessionIdentity)
        );
        assert_eq!(
            derive_d1_row_write_plan(
                &target(),
                &"a".repeat(64),
                D1WriteStatementKind::Delete,
                "DELETE FROM t",
                &[],
                0,
            ),
            Err(D1RowWritePlanError::InvalidRowLimit)
        );
    }
}
