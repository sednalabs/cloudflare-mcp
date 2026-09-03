//! Closed inspection projection for attempt artifacts sharing D1 custody.
//!
//! Row-DML and curated target-wide attempts have distinct strict schemas. The
//! storage layer uses only this aggregate projection to validate placement and
//! claimant linkage; it never treats one family as the other's authority.

use crate::d1_dml_attempt_custody::{
    D1DmlAttemptPhase, inspect_d1_dml_attempt_state, validate_d1_dml_attempt_audit_binding,
};
use crate::d1_target_wide_attempt_custody::{
    D1_TARGET_WIDE_ATTEMPT_CUSTODY_OPERATION, inspect_d1_target_wide_attempt_state,
    validate_d1_target_wide_attempt_successor,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1AttemptArtifactReceipt {
    pub(crate) family: &'static str,
    pub(crate) target_key_sha256: String,
    pub(crate) execute_plan_sha256: String,
    pub(crate) operation_id_sha256: String,
    pub(crate) execution_attempt_id_sha256: String,
    pub(crate) provider_request_id_sha256: String,
    pub(crate) attempt_binding_sha256: String,
    pub(crate) phase: D1DmlAttemptPhase,
}

pub(crate) fn inspect_d1_attempt_artifact(
    bytes: &[u8],
) -> Result<D1AttemptArtifactReceipt, &'static str> {
    if let Ok(product) = inspect_d1_dml_attempt_state(bytes) {
        validate_d1_dml_attempt_audit_binding(product.receipt())
            .map_err(|_| "row-DML attempt binding did not rederive")?;
        let receipt = product.receipt();
        return Ok(D1AttemptArtifactReceipt {
            family: receipt.operation,
            target_key_sha256: receipt.target_key_sha256.clone(),
            execute_plan_sha256: receipt.execute_plan_sha256.clone(),
            operation_id_sha256: receipt.operation_id_sha256.clone(),
            execution_attempt_id_sha256: receipt.execution_attempt_id_sha256.clone(),
            provider_request_id_sha256: receipt.provider_request_id_sha256.clone(),
            attempt_binding_sha256: receipt.attempt_binding_sha256.clone(),
            phase: receipt.phase,
        });
    }
    if let Ok(product) = inspect_d1_target_wide_attempt_state(bytes) {
        let receipt = product.receipt();
        return Ok(D1AttemptArtifactReceipt {
            family: D1_TARGET_WIDE_ATTEMPT_CUSTODY_OPERATION,
            target_key_sha256: receipt.target_key_sha256.clone(),
            execute_plan_sha256: receipt.intended_plan_sha256.clone(),
            operation_id_sha256: receipt.operation_id_sha256.clone(),
            execution_attempt_id_sha256: receipt.execution_attempt_id_sha256.clone(),
            provider_request_id_sha256: receipt.provider_request_id_sha256.clone(),
            attempt_binding_sha256: receipt.attempt_binding_sha256.clone(),
            phase: receipt.phase,
        });
    }
    Err("attempt artifact matched no supported strict custody schema")
}

pub(crate) fn validate_d1_attempt_artifact_successor(
    expected: &[u8],
    successor: &[u8],
) -> Result<(), &'static str> {
    let expected_receipt = inspect_d1_attempt_artifact(expected)?;
    let successor_receipt = inspect_d1_attempt_artifact(successor)?;
    if expected_receipt.family != successor_receipt.family {
        return Err("DML attempt successor changed artifact family");
    }
    match expected_receipt.family {
        crate::d1_dml_attempt_custody::D1_DML_ATTEMPT_CUSTODY_OPERATION => {
            crate::d1_dml_attempt_custody::validate_d1_dml_attempt_successor(expected, successor)
                .map_err(|_| "row-DML attempt successor was not the exact incumbent transition")
        }
        D1_TARGET_WIDE_ATTEMPT_CUSTODY_OPERATION => validate_d1_target_wide_attempt_successor(
            expected, successor,
        )
        .map_err(|_| "target-wide D1 attempt successor was not the exact incumbent transition"),
        _ => Err("DML attempt successor used an unsupported artifact family"),
    }
}
