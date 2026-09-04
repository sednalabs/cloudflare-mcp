//! Inert Cloudflare adapter-boundary evidence for one D1 row write.
//!
//! This module intentionally has no client call, tool registration, custody,
//! persistence, CAS, or deployment wiring.  It only defines the strict
//! response and causal-witness seam that a later guarded adapter may consume.
//! A witness can be created only from the exact response bytes and a complete
//! lifecycle; caller-provided digests, counts, status summaries, or parsed
//! outcome objects are never accepted.

use mcp_toolkit_core::response_contract::MutationApplyStatus;
use serde::Deserialize;
use serde_json::Value;

use super::client::decode_json_rejecting_duplicate_object_keys;
use crate::d1_execute_write::{
    D1ExecuteWriteOutcome, D1WriteResultClassification, classify_d1_execute_write_result,
};
use crate::d1_row_write_plan::D1RowWritePlan;
use crate::d1_target::D1TargetIdentity;
use crate::tools::sha256_bytes_hex;

const MAX_D1_ROW_WRITE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct D1RowWriteLifecycle {
    dispatch_attempted: bool,
    response_received: bool,
    body_complete: bool,
    http_status: Option<u16>,
    apply_status: MutationApplyStatus,
}

impl D1RowWriteLifecycle {
    pub(super) const fn pre_dispatch() -> Self {
        Self {
            dispatch_attempted: false,
            response_received: false,
            body_complete: false,
            http_status: None,
            apply_status: MutationApplyStatus::RejectedBeforeApply,
        }
    }

    pub(super) const fn response_lost() -> Self {
        Self {
            dispatch_attempted: true,
            response_received: false,
            body_complete: false,
            http_status: None,
            apply_status: MutationApplyStatus::UncertainAfterDispatch,
        }
    }

    pub(super) const fn body_incomplete(http_status: u16) -> Self {
        Self {
            dispatch_attempted: true,
            response_received: true,
            body_complete: false,
            http_status: Some(http_status),
            apply_status: MutationApplyStatus::UncertainAfterDispatch,
        }
    }

    pub(super) const fn applied(http_status: u16) -> Self {
        Self {
            dispatch_attempted: true,
            response_received: true,
            body_complete: true,
            http_status: Some(http_status),
            apply_status: MutationApplyStatus::Applied,
        }
    }

    fn is_complete_success(self) -> bool {
        self.dispatch_attempted
            && self.response_received
            && self.body_complete
            && self
                .http_status
                .is_some_and(|status| (200..300).contains(&status))
            && self.apply_status == MutationApplyStatus::Applied
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum D1RowWriteEvidenceError {
    ResponseBodyTooLarge,
    ResponseBodyNotUtf8,
    ResponseDuplicateObjectKey,
    ResponseNestingLimitExceeded,
    ResponseMalformed,
    EnvelopeNotStrict,
    EnvelopeNotSuccessful,
    EnvelopeErrorsNotEmpty,
    ProviderOutcomeAmbiguous(D1WriteResultClassification),
    LifecycleIncomplete,
    IdentityMalformed,
    IdentityReused,
    TargetPlanMismatch,
}

/// The outer Cloudflare response is intentionally stricter than the generic
/// compatibility envelope.  In particular, omitted/null errors and unknown
/// fields cannot be normalised into apparent success.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictD1RowWriteEnvelope {
    success: bool,
    result: Option<Value>,
    errors: Option<Value>,
}

/// Private authoritative outcome parsed from the response's exact result set.
/// It is not deserializable and cannot be supplied by an orchestration caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct D1RowWriteCausalWitness {
    target_key_sha256: String,
    plan_sha256: String,
    operation_id_sha256: String,
    execution_attempt_id_sha256: String,
    provider_request_id_sha256: String,
    provider_outcome: D1ExecuteWriteOutcome,
    response_body_sha256: String,
    response_body_size_bytes: usize,
    http_status: u16,
    lifecycle: D1RowWriteLifecycle,
}

fn valid_opaque_identity(value: &str) -> bool {
    (1..=256).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn decode_strict_provider_outcome(
    body: &str,
    statement_kind: crate::d1_execute_write::D1WriteStatementKind,
) -> Result<D1ExecuteWriteOutcome, D1RowWriteEvidenceError> {
    let value = decode_json_rejecting_duplicate_object_keys(body).map_err(|error| match error {
        super::client::DuplicateSafeJsonError::DuplicateObjectKey => {
            D1RowWriteEvidenceError::ResponseDuplicateObjectKey
        }
        super::client::DuplicateSafeJsonError::NestingDepthExceeded => {
            D1RowWriteEvidenceError::ResponseNestingLimitExceeded
        }
        super::client::DuplicateSafeJsonError::Malformed(_) => {
            D1RowWriteEvidenceError::ResponseMalformed
        }
    })?;
    let envelope: StrictD1RowWriteEnvelope =
        serde_json::from_value(value).map_err(|_| D1RowWriteEvidenceError::EnvelopeNotStrict)?;
    if !envelope.success {
        return Err(D1RowWriteEvidenceError::EnvelopeNotSuccessful);
    }
    match envelope.errors {
        Some(Value::Array(errors)) if errors.is_empty() => {}
        _ => return Err(D1RowWriteEvidenceError::EnvelopeErrorsNotEmpty),
    }
    let result = envelope
        .result
        .ok_or(D1RowWriteEvidenceError::EnvelopeNotStrict)?;
    classify_d1_execute_write_result(statement_kind, &result)
        .map_err(|error| D1RowWriteEvidenceError::ProviderOutcomeAmbiguous(error.classification))
}

fn validate_identities(
    operation_id: &str,
    execution_attempt_id: &str,
    provider_request_id: &str,
) -> Result<(), D1RowWriteEvidenceError> {
    if !valid_opaque_identity(operation_id)
        || !valid_opaque_identity(execution_attempt_id)
        || !valid_opaque_identity(provider_request_id)
    {
        return Err(D1RowWriteEvidenceError::IdentityMalformed);
    }
    if operation_id == execution_attempt_id
        || operation_id == provider_request_id
        || execution_attempt_id == provider_request_id
    {
        return Err(D1RowWriteEvidenceError::IdentityReused);
    }
    Ok(())
}

/// Construct authoritative evidence inside the Cloudflare adapter boundary.
/// The body is the complete bytes read from the provider; all hashes and size
/// fields are derived here.  A response-loss or partial-body lifecycle never
/// yields a witness, even when a syntactically valid body is supplied.
pub(super) fn causal_witness_from_adapter_evidence(
    target: &D1TargetIdentity,
    plan: &D1RowWritePlan,
    operation_id: &str,
    execution_attempt_id: &str,
    provider_request_id: &str,
    response_body: &[u8],
    lifecycle: D1RowWriteLifecycle,
) -> Result<D1RowWriteCausalWitness, D1RowWriteEvidenceError> {
    if !lifecycle.is_complete_success() {
        return Err(D1RowWriteEvidenceError::LifecycleIncomplete);
    }
    if target.target_key_sha256() != *plan.target_key_sha256() {
        return Err(D1RowWriteEvidenceError::TargetPlanMismatch);
    }
    validate_identities(operation_id, execution_attempt_id, provider_request_id)?;
    if response_body.len() > MAX_D1_ROW_WRITE_RESPONSE_BYTES {
        return Err(D1RowWriteEvidenceError::ResponseBodyTooLarge);
    }
    let body = std::str::from_utf8(response_body)
        .map_err(|_| D1RowWriteEvidenceError::ResponseBodyNotUtf8)?;
    let provider_outcome = decode_strict_provider_outcome(body, plan.statement_kind())?;
    let http_status = lifecycle
        .http_status
        .expect("complete success lifecycle always has HTTP status");
    Ok(D1RowWriteCausalWitness {
        target_key_sha256: target.target_key_sha256(),
        plan_sha256: plan.plan_sha256().to_string(),
        operation_id_sha256: sha256_bytes_hex(operation_id.as_bytes()),
        execution_attempt_id_sha256: sha256_bytes_hex(execution_attempt_id.as_bytes()),
        provider_request_id_sha256: sha256_bytes_hex(provider_request_id.as_bytes()),
        provider_outcome,
        response_body_sha256: sha256_bytes_hex(response_body),
        response_body_size_bytes: response_body.len(),
        http_status,
        lifecycle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::d1_execute_write::{D1WriteStatementKind, derive_d1_execute_write_plan};
    use crate::d1_row_write_plan::derive_d1_row_write_plan;
    use crate::d1_target::normalize_d1_target;
    use serde_json::json;

    const TARGET_DATABASE: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn target() -> D1TargetIdentity {
        normalize_d1_target("acct-1", TARGET_DATABASE).expect("fixture target is canonical")
    }

    fn plan() -> D1RowWritePlan {
        derive_d1_row_write_plan(
            &target(),
            &"a".repeat(64),
            D1WriteStatementKind::Update,
            "UPDATE t SET enabled = ? WHERE id = ?",
            &[json!(true), json!("fixture")],
            100,
        )
        .expect("fixture plan is canonical")
    }

    fn body() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "success": true,
            "result": [{
                "success": true,
                "errors": [],
                "results": [],
                "meta": {
                    "served_by_primary": true,
                    "changed_db": true,
                    "changes": 1,
                    "rows_written": 1
                }
            }],
            "errors": []
        }))
        .expect("fixture JSON")
    }

    fn witness() -> D1RowWriteCausalWitness {
        causal_witness_from_adapter_evidence(
            &target(),
            &plan(),
            "operation-1",
            "attempt-1",
            "provider-request-1",
            &body(),
            D1RowWriteLifecycle::applied(200),
        )
        .expect("valid witness")
    }

    #[test]
    fn valid_complete_response_produces_private_witness_with_derived_evidence() {
        let witness = witness();
        assert_eq!(witness.target_key_sha256.len(), 64);
        assert_eq!(witness.plan_sha256.len(), 64);
        assert_eq!(witness.operation_id_sha256.len(), 64);
        assert_eq!(witness.execution_attempt_id_sha256.len(), 64);
        assert_eq!(witness.provider_request_id_sha256.len(), 64);
        assert_eq!(witness.response_body_sha256, sha256_bytes_hex(&body()));
        assert_eq!(witness.response_body_size_bytes, body().len());
        assert_eq!(witness.http_status, 200);
        assert_eq!(witness.provider_outcome.changes, 1);
    }

    #[test]
    fn response_loss_and_partial_body_never_create_witness() {
        for lifecycle in [
            D1RowWriteLifecycle::pre_dispatch(),
            D1RowWriteLifecycle::response_lost(),
            D1RowWriteLifecycle::body_incomplete(200),
        ] {
            assert_eq!(
                causal_witness_from_adapter_evidence(
                    &target(),
                    &plan(),
                    "operation-1",
                    "attempt-1",
                    "provider-request-1",
                    &body(),
                    lifecycle,
                ),
                Err(D1RowWriteEvidenceError::LifecycleIncomplete)
            );
        }
    }

    #[test]
    fn strict_envelope_rejects_duplicate_unknown_missing_or_nonempty_errors() {
        let cases = [
            (
                br#"{"success":true,"result":[],"errors":[],"unknown":1}"#.to_vec(),
                D1RowWriteEvidenceError::EnvelopeNotStrict,
            ),
            (
                br#"{"success":true,"result":[],"errors":null}"#.to_vec(),
                D1RowWriteEvidenceError::EnvelopeErrorsNotEmpty,
            ),
            (
                br#"{"success":true,"result":[],"errors":[{"code":1}]}"#.to_vec(),
                D1RowWriteEvidenceError::EnvelopeErrorsNotEmpty,
            ),
            (
                br#"{"success":true,"result":[],"errors":[] ,"errors":[]}"#.to_vec(),
                D1RowWriteEvidenceError::ResponseDuplicateObjectKey,
            ),
        ];
        for (body, expected) in cases {
            assert_eq!(
                causal_witness_from_adapter_evidence(
                    &target(),
                    &plan(),
                    "operation-1",
                    "attempt-1",
                    "provider-request-1",
                    &body,
                    D1RowWriteLifecycle::applied(200),
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn strict_provider_outcome_rejects_failure_and_contradictory_metadata() {
        let mut failure = body();
        let failure_value: Value = serde_json::from_slice(&failure).expect("fixture JSON");
        let mut failure_value = failure_value;
        failure_value["result"][0]["success"] = json!(false);
        failure = serde_json::to_vec(&failure_value).expect("fixture JSON");
        assert!(matches!(
            causal_witness_from_adapter_evidence(
                &target(),
                &plan(),
                "operation-1",
                "attempt-1",
                "provider-request-1",
                &failure,
                D1RowWriteLifecycle::applied(200),
            ),
            Err(D1RowWriteEvidenceError::ProviderOutcomeAmbiguous(
                D1WriteResultClassification::InnerStatementFailureOrMissingSuccess
            ))
        ));

        let contradictory = br#"{"success":true,"result":[{"success":true,"errors":[],"results":[],"meta":{"served_by_primary":true,"changed_db":false,"changes":1,"rows_written":0}}],"errors":[]}"#;
        assert!(matches!(
            causal_witness_from_adapter_evidence(
                &target(),
                &plan(),
                "operation-1",
                "attempt-1",
                "provider-request-1",
                contradictory,
                D1RowWriteLifecycle::applied(200),
            ),
            Err(D1RowWriteEvidenceError::ProviderOutcomeAmbiguous(
                D1WriteResultClassification::WriteMetadataContradictory
            ))
        ));
    }

    #[test]
    fn witness_rejects_reused_or_malformed_identities_and_target_mismatch() {
        assert_eq!(
            causal_witness_from_adapter_evidence(
                &target(),
                &plan(),
                "same",
                "same",
                "provider-request-1",
                &body(),
                D1RowWriteLifecycle::applied(200),
            ),
            Err(D1RowWriteEvidenceError::IdentityReused)
        );
        assert_eq!(
            causal_witness_from_adapter_evidence(
                &target(),
                &plan(),
                "operation\n",
                "attempt-1",
                "provider-request-1",
                &body(),
                D1RowWriteLifecycle::applied(200),
            ),
            Err(D1RowWriteEvidenceError::IdentityMalformed)
        );
        let other = normalize_d1_target("acct-2", TARGET_DATABASE).expect("fixture target");
        assert_eq!(
            causal_witness_from_adapter_evidence(
                &other,
                &plan(),
                "operation-1",
                "attempt-1",
                "provider-request-1",
                &body(),
                D1RowWriteLifecycle::applied(200),
            ),
            Err(D1RowWriteEvidenceError::TargetPlanMismatch)
        );
    }

    #[test]
    fn no_caller_supplied_digest_can_change_witness_identity() {
        let first = witness();
        let mut changed_body = body();
        changed_body.push(b' ');
        let second = causal_witness_from_adapter_evidence(
            &target(),
            &plan(),
            "operation-1",
            "attempt-1",
            "provider-request-1",
            &changed_body,
            D1RowWriteLifecycle::applied(200),
        )
        .expect("whitespace remains valid JSON");
        assert_ne!(first.response_body_sha256, second.response_body_sha256);
        assert_ne!(
            first.response_body_size_bytes,
            second.response_body_size_bytes
        );
    }

    #[allow(dead_code)]
    fn _reuse_existing_planner_type_for_compile_guard() {
        let _ = derive_d1_execute_write_plan;
    }
}
