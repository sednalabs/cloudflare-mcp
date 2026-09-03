//! Exact Prepared custody for curated target-wide D1 rename/delete attempts.
//!
//! This boundary binds the complete static consent product and three opaque
//! caller identities into one canonical private artifact. It deliberately has
//! no dispatch, provider-response, readback, terminal, recovery, or retry path.

use std::collections::BTreeSet;

use rmcp::model::CallToolResult;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::d1_dml_attempt_custody::{
    D1_DML_ATTEMPT_STATE_BYTE_CAP, D1DmlAttemptIdentities, D1DmlAttemptPhase,
};
use crate::d1_dml_custody_layout::{D1_DML_CUSTODY_LAYOUT_SHA256, D1_DML_CUSTODY_LAYOUT_VERSION};
use crate::d1_dml_identity_claimant::{
    D1DmlIdentityClaimantSet, derive_d1_dml_identity_claimant_set,
};
use crate::d1_dml_identity_reservation::{
    converge_bound_d1_dml_identity_claimants, converge_pending_d1_dml_identity_claimants,
};
use crate::d1_migration_lease::D1TargetMutationGuard;
use crate::d1_opaque_identity::valid_d1_opaque_identity;
use crate::d1_target::{D1TargetIdentity, normalize_d1_target};
use crate::d1_target_wide_mutation::{
    D1TargetWideIntendedPlan, TARGET_WIDE_CONSENT_VERSION, TARGET_WIDE_OPERATION_VERSION,
    rederive_d1_target_wide_intended_plan,
};

pub(crate) const D1_TARGET_WIDE_ATTEMPT_CUSTODY_OPERATION: &str = "d1_target_wide_attempt_custody";
const TARGET_WIDE_ATTEMPT_VERSION: u8 = 1;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct D1TargetWideAttemptState {
    version: u8,
    operation: String,
    consent_version: u8,
    operation_version: u8,
    layout_version: u8,
    layout_sha256: String,
    target_operation: String,
    target_key_sha256: String,
    intended_plan_sha256: String,
    consent_binding_sha256: String,
    confirmation_token_sha256: String,
    normalized_target_sha256: String,
    requested_change_sha256: String,
    reason_sha256: String,
    operation_id_sha256: String,
    execution_attempt_id_sha256: String,
    provider_request_id_sha256: String,
    attempt_binding_sha256: String,
    phase: D1DmlAttemptPhase,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1TargetWidePreparedTransition {
    Prepared,
    ExactReplay,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWidePreparedReceipt {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) consent_version: u8,
    pub(crate) operation_version: u8,
    pub(crate) target_operation: String,
    pub(crate) layout_version: u8,
    pub(crate) layout_sha256: String,
    pub(crate) phase: D1DmlAttemptPhase,
    pub(crate) transition: D1TargetWidePreparedTransition,
    pub(crate) exact_replay: bool,
    pub(crate) target_key_sha256: String,
    pub(crate) intended_plan_sha256: String,
    pub(crate) consent_binding_sha256: String,
    pub(crate) confirmation_token_sha256: String,
    pub(crate) normalized_target_sha256: String,
    pub(crate) requested_change_sha256: String,
    pub(crate) reason_sha256: String,
    pub(crate) operation_id_sha256: String,
    pub(crate) execution_attempt_id_sha256: String,
    pub(crate) provider_request_id_sha256: String,
    pub(crate) attempt_binding_sha256: String,
    pub(crate) state_sha256: String,
    pub(crate) state_size_bytes: usize,
    pub(crate) state_byte_cap: usize,
    pub(crate) provider_calls: u8,
    pub(crate) provider_mutations: u8,
    pub(crate) automatic_retry_permitted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1TargetWidePreparedProduct {
    receipt: D1TargetWidePreparedReceipt,
    state_bytes: Vec<u8>,
}

impl D1TargetWidePreparedProduct {
    pub(crate) fn receipt(&self) -> &D1TargetWidePreparedReceipt {
        &self.receipt
    }

    pub(crate) fn state_bytes(&self) -> &[u8] {
        &self.state_bytes
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1TargetWidePreparedClassification {
    TargetIdentityInvalid,
    IntendedPlanInvalid,
    ConsentMismatch,
    OpaqueIdentityInvalid,
    OpaqueIdentityDuplicate,
    RestoredStateRequired,
    RestoredStateTooLarge,
    RestoredStateMalformed,
    RestoredStateNonCanonical,
    RestoredStateUnsupported,
    RestoredStateContradictory,
    ReplayConflict,
    StateLimitExceeded,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWidePreparedError {
    pub(crate) code: &'static str,
    pub(crate) classification: D1TargetWidePreparedClassification,
    pub(crate) message: &'static str,
}

#[derive(Debug, Clone)]
struct PreparedBinding {
    consent_version: u8,
    operation_version: u8,
    target_operation: String,
    target_key_sha256: String,
    intended_plan_sha256: String,
    consent_binding_sha256: String,
    confirmation_token_sha256: String,
    normalized_target_sha256: String,
    requested_change_sha256: String,
    reason_sha256: String,
    operation_id_sha256: String,
    execution_attempt_id_sha256: String,
    provider_request_id_sha256: String,
    attempt_binding_sha256: String,
}

#[derive(Serialize)]
struct D1TargetWideAttemptBindingMaterial<'a> {
    version: u8,
    operation: &'a str,
    layout_version: u8,
    layout_sha256: &'a str,
    consent_version: u8,
    operation_version: u8,
    target_operation: &'a str,
    target_key_sha256: &'a str,
    intended_plan_sha256: &'a str,
    consent_binding_sha256: &'a str,
    confirmation_token_sha256: &'a str,
    normalized_target_sha256: &'a str,
    requested_change_sha256: &'a str,
    reason_sha256: &'a str,
    operation_id_sha256: &'a str,
    execution_attempt_id_sha256: &'a str,
    provider_request_id_sha256: &'a str,
}

pub(crate) fn prepare_d1_target_wide_attempt(
    target: &D1TargetIdentity,
    intended_plan: &D1TargetWideIntendedPlan,
    confirmation_token: &str,
    identities: D1DmlAttemptIdentities<'_>,
    restored_state: Option<&[u8]>,
) -> Result<D1TargetWidePreparedProduct, D1TargetWidePreparedError> {
    let binding = derive_binding(target, intended_plan, confirmation_token, identities)?;
    match restored_state {
        None => product(
            state_from_binding(&binding),
            D1TargetWidePreparedTransition::Prepared,
            false,
        ),
        Some(bytes) => {
            let state = restore_exact_state(bytes, &binding)?;
            product(state, D1TargetWidePreparedTransition::ExactReplay, true)
        }
    }
}

pub(crate) fn inspect_d1_target_wide_attempt_state(
    bytes: &[u8],
) -> Result<D1TargetWidePreparedProduct, D1TargetWidePreparedError> {
    let state = parse_canonical_state(bytes)?;
    product(state, D1TargetWidePreparedTransition::ExactReplay, true)
}

pub(crate) fn install_d1_target_wide_prepared_custody(
    guard: &D1TargetMutationGuard,
    target: &D1TargetIdentity,
    intended_plan: &D1TargetWideIntendedPlan,
    confirmation_token: &str,
    identities: D1DmlAttemptIdentities<'_>,
) -> Result<D1TargetWidePreparedProduct, CallToolResult> {
    guard.assert_exact_target(target)?;
    let prepared =
        prepare_d1_target_wide_attempt(target, intended_plan, confirmation_token, identities, None)
            .map_err(prepared_error_result)?;
    guard.ensure_target_wide_d1_dml_custody_layout()?;
    let binding = &prepared.receipt.attempt_binding_sha256;
    let incumbent = guard.read_d1_dml_attempt_state(binding)?;
    if let Some(bytes) = incumbent.as_deref() {
        prepare_d1_target_wide_attempt(
            target,
            intended_plan,
            confirmation_token,
            identities,
            Some(bytes),
        )
        .map_err(prepared_error_result)?;
    } else {
        guard.preflight_d1_dml_attempt_capacity(binding)?;
    }
    let claimant_set =
        derive_claimant_set(target, intended_plan, identities).map_err(prepared_error_result)?;
    converge_pending_d1_dml_identity_claimants(guard, &claimant_set, |code, message, phase| {
        target_wide_claimant_error_result(intended_plan, code, message, phase)
    })?;
    converge_bound_d1_dml_identity_claimants(
        guard,
        &claimant_set,
        &prepared.receipt.attempt_binding_sha256,
        |code, message, phase| {
            target_wide_claimant_error_result(intended_plan, code, message, phase)
        },
    )?;

    if incumbent.is_none() {
        guard.create_d1_dml_attempt_state(binding, prepared.state_bytes())?;
    }
    let readback = guard.read_d1_dml_attempt_state(binding)?.ok_or_else(|| {
        prepared_store_error(
            intended_plan,
            "d1.target_wide_prepared_custody_unproven",
            "Prepared attempt state was absent after create-once convergence",
            "prepared_readback",
        )
    })?;
    let restored = prepare_d1_target_wide_attempt(
        target,
        intended_plan,
        confirmation_token,
        identities,
        Some(&readback),
    )
    .map_err(prepared_error_result)?;
    converge_bound_d1_dml_identity_claimants(
        guard,
        &claimant_set,
        binding,
        |code, message, phase| {
            target_wide_claimant_error_result(intended_plan, code, message, phase)
        },
    )?;
    guard.revalidate()?;
    Ok(restored)
}

fn derive_claimant_set(
    target: &D1TargetIdentity,
    intended_plan: &D1TargetWideIntendedPlan,
    identities: D1DmlAttemptIdentities<'_>,
) -> Result<D1DmlIdentityClaimantSet, D1TargetWidePreparedError> {
    derive_d1_dml_identity_claimant_set(target, &intended_plan.plan_sha256, identities).map_err(
        |_| {
            prepared_error(
                D1TargetWidePreparedClassification::OpaqueIdentityInvalid,
                "target-wide identity claimant set was not exact canonical input",
            )
        },
    )
}

fn derive_binding(
    target: &D1TargetIdentity,
    intended_plan: &D1TargetWideIntendedPlan,
    confirmation_token: &str,
    identities: D1DmlAttemptIdentities<'_>,
) -> Result<PreparedBinding, D1TargetWidePreparedError> {
    let normalized =
        normalize_d1_target(&target.account_id, &target.database_id).map_err(|_| {
            prepared_error(
                D1TargetWidePreparedClassification::TargetIdentityInvalid,
                "D1 target identity was not exact canonical input",
            )
        })?;
    if &normalized != target {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::TargetIdentityInvalid,
            "D1 target identity was not exact canonical input",
        ));
    }
    let supplied_consent = &intended_plan.consent_binding;
    let expected = rederive_d1_target_wide_intended_plan(
        target,
        supplied_consent.operation,
        &supplied_consent.requested_change,
        supplied_consent.reason.as_deref(),
    )
    .map_err(|_| {
        prepared_error(
            D1TargetWidePreparedClassification::IntendedPlanInvalid,
            "target-wide intended plan could not be rederived from canonical request facts",
        )
    })?;
    if supplied_consent.consent_version != TARGET_WIDE_CONSENT_VERSION
        || supplied_consent.operation_version != TARGET_WIDE_OPERATION_VERSION
        || intended_plan != &expected
    {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::IntendedPlanInvalid,
            "target-wide intended plan was not the complete current canonical six-step consent product",
        ));
    }
    let expected_token = expected.confirmation_token();
    if confirmation_token != expected_token {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::ConsentMismatch,
            "target-wide confirmation token did not match the rederived canonical consent product",
        ));
    }
    let consent = &expected.consent_binding;
    let target_operation = consent.operation;
    let opaque = [
        identities.operation_id,
        identities.execution_attempt_id,
        identities.provider_request_id,
    ];
    if opaque.iter().any(|value| !valid_d1_opaque_identity(value)) {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::OpaqueIdentityInvalid,
            "preallocated target-wide attempt identities were not exact bounded opaque identifiers",
        ));
    }
    if opaque.into_iter().collect::<BTreeSet<_>>().len() != 3 {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::OpaqueIdentityDuplicate,
            "preallocated target-wide attempt identities were not pairwise distinct",
        ));
    }

    let target_key_sha256 = target.target_key_sha256();
    let consent_binding_sha256 = hash_serialized(consent);
    let confirmation_token_sha256 = hash_bytes(confirmation_token.as_bytes());
    let normalized_target_sha256 = hash_serialized(&consent.normalized_target);
    let requested_change_sha256 = hash_serialized(&consent.requested_change);
    let reason_sha256 = hash_serialized(&consent.reason);
    let operation_id_sha256 = hash_bytes(identities.operation_id.as_bytes());
    let execution_attempt_id_sha256 = hash_bytes(identities.execution_attempt_id.as_bytes());
    let provider_request_id_sha256 = hash_bytes(identities.provider_request_id.as_bytes());
    let attempt_binding_sha256 = hash_serialized(&D1TargetWideAttemptBindingMaterial {
        version: TARGET_WIDE_ATTEMPT_VERSION,
        operation: D1_TARGET_WIDE_ATTEMPT_CUSTODY_OPERATION,
        layout_version: D1_DML_CUSTODY_LAYOUT_VERSION,
        layout_sha256: D1_DML_CUSTODY_LAYOUT_SHA256,
        consent_version: consent.consent_version,
        operation_version: consent.operation_version,
        target_operation,
        target_key_sha256: &target_key_sha256,
        intended_plan_sha256: &expected.plan_sha256,
        consent_binding_sha256: &consent_binding_sha256,
        confirmation_token_sha256: &confirmation_token_sha256,
        normalized_target_sha256: &normalized_target_sha256,
        requested_change_sha256: &requested_change_sha256,
        reason_sha256: &reason_sha256,
        operation_id_sha256: &operation_id_sha256,
        execution_attempt_id_sha256: &execution_attempt_id_sha256,
        provider_request_id_sha256: &provider_request_id_sha256,
    });
    Ok(PreparedBinding {
        consent_version: consent.consent_version,
        operation_version: consent.operation_version,
        target_operation: target_operation.to_string(),
        target_key_sha256,
        intended_plan_sha256: expected.plan_sha256,
        consent_binding_sha256,
        confirmation_token_sha256,
        normalized_target_sha256,
        requested_change_sha256,
        reason_sha256,
        operation_id_sha256,
        execution_attempt_id_sha256,
        provider_request_id_sha256,
        attempt_binding_sha256,
    })
}

fn state_from_binding(binding: &PreparedBinding) -> D1TargetWideAttemptState {
    D1TargetWideAttemptState {
        version: TARGET_WIDE_ATTEMPT_VERSION,
        operation: D1_TARGET_WIDE_ATTEMPT_CUSTODY_OPERATION.to_string(),
        consent_version: binding.consent_version,
        operation_version: binding.operation_version,
        layout_version: D1_DML_CUSTODY_LAYOUT_VERSION,
        layout_sha256: D1_DML_CUSTODY_LAYOUT_SHA256.to_string(),
        target_operation: binding.target_operation.clone(),
        target_key_sha256: binding.target_key_sha256.clone(),
        intended_plan_sha256: binding.intended_plan_sha256.clone(),
        consent_binding_sha256: binding.consent_binding_sha256.clone(),
        confirmation_token_sha256: binding.confirmation_token_sha256.clone(),
        normalized_target_sha256: binding.normalized_target_sha256.clone(),
        requested_change_sha256: binding.requested_change_sha256.clone(),
        reason_sha256: binding.reason_sha256.clone(),
        operation_id_sha256: binding.operation_id_sha256.clone(),
        execution_attempt_id_sha256: binding.execution_attempt_id_sha256.clone(),
        provider_request_id_sha256: binding.provider_request_id_sha256.clone(),
        attempt_binding_sha256: binding.attempt_binding_sha256.clone(),
        phase: D1DmlAttemptPhase::Prepared,
    }
}

fn restore_exact_state(
    bytes: &[u8],
    binding: &PreparedBinding,
) -> Result<D1TargetWideAttemptState, D1TargetWidePreparedError> {
    let state = parse_canonical_state(bytes)?;
    if state != state_from_binding(binding) {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::ReplayConflict,
            "target-wide Prepared replay contradicted the exact consent, plan, target, change, reason, or identities",
        ));
    }
    Ok(state)
}

fn parse_canonical_state(
    bytes: &[u8],
) -> Result<D1TargetWideAttemptState, D1TargetWidePreparedError> {
    if bytes.is_empty() {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::RestoredStateRequired,
            "one physically present target-wide attempt state was required",
        ));
    }
    if bytes.len() > D1_DML_ATTEMPT_STATE_BYTE_CAP {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::RestoredStateTooLarge,
            "target-wide attempt state exceeded the exact byte cap",
        ));
    }
    let state = serde_json::from_slice::<D1TargetWideAttemptState>(bytes).map_err(|_| {
        prepared_error(
            D1TargetWidePreparedClassification::RestoredStateMalformed,
            "target-wide attempt state was malformed or outside the closed schema",
        )
    })?;
    if canonical_state_bytes(&state)? != bytes {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::RestoredStateNonCanonical,
            "target-wide attempt state was not exact canonical JSON",
        ));
    }
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &D1TargetWideAttemptState) -> Result<(), D1TargetWidePreparedError> {
    if state.version != TARGET_WIDE_ATTEMPT_VERSION
        || state.operation != D1_TARGET_WIDE_ATTEMPT_CUSTODY_OPERATION
        || state.consent_version != TARGET_WIDE_CONSENT_VERSION
        || state.operation_version != TARGET_WIDE_OPERATION_VERSION
        || state.layout_version != D1_DML_CUSTODY_LAYOUT_VERSION
        || state.layout_sha256 != D1_DML_CUSTODY_LAYOUT_SHA256
    {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::RestoredStateUnsupported,
            "target-wide attempt state version, operation, or layout was unsupported",
        ));
    }
    if !matches!(
        state.target_operation.as_str(),
        "d1_rename_database" | "d1_delete_database"
    ) || state.phase != D1DmlAttemptPhase::Prepared
        || ![
            &state.layout_sha256,
            &state.target_key_sha256,
            &state.intended_plan_sha256,
            &state.consent_binding_sha256,
            &state.confirmation_token_sha256,
            &state.normalized_target_sha256,
            &state.requested_change_sha256,
            &state.reason_sha256,
            &state.operation_id_sha256,
            &state.execution_attempt_id_sha256,
            &state.provider_request_id_sha256,
            &state.attempt_binding_sha256,
        ]
        .into_iter()
        .all(|value| valid_sha256(value))
    {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::RestoredStateContradictory,
            "target-wide attempt state contradicted the closed Prepared product",
        ));
    }
    let expected_binding = hash_serialized(&D1TargetWideAttemptBindingMaterial {
        version: state.version,
        operation: &state.operation,
        layout_version: state.layout_version,
        layout_sha256: &state.layout_sha256,
        consent_version: state.consent_version,
        operation_version: state.operation_version,
        target_operation: &state.target_operation,
        target_key_sha256: &state.target_key_sha256,
        intended_plan_sha256: &state.intended_plan_sha256,
        consent_binding_sha256: &state.consent_binding_sha256,
        confirmation_token_sha256: &state.confirmation_token_sha256,
        normalized_target_sha256: &state.normalized_target_sha256,
        requested_change_sha256: &state.requested_change_sha256,
        reason_sha256: &state.reason_sha256,
        operation_id_sha256: &state.operation_id_sha256,
        execution_attempt_id_sha256: &state.execution_attempt_id_sha256,
        provider_request_id_sha256: &state.provider_request_id_sha256,
    });
    if state.attempt_binding_sha256 != expected_binding {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::RestoredStateContradictory,
            "target-wide attempt binding did not rederive from physical state",
        ));
    }
    Ok(())
}

fn product(
    state: D1TargetWideAttemptState,
    transition: D1TargetWidePreparedTransition,
    exact_replay: bool,
) -> Result<D1TargetWidePreparedProduct, D1TargetWidePreparedError> {
    validate_state(&state)?;
    let state_bytes = canonical_state_bytes(&state)?;
    let receipt = D1TargetWidePreparedReceipt {
        version: state.version,
        operation: D1_TARGET_WIDE_ATTEMPT_CUSTODY_OPERATION,
        consent_version: state.consent_version,
        operation_version: state.operation_version,
        target_operation: state.target_operation.clone(),
        layout_version: state.layout_version,
        layout_sha256: state.layout_sha256.clone(),
        phase: state.phase,
        transition,
        exact_replay,
        target_key_sha256: state.target_key_sha256.clone(),
        intended_plan_sha256: state.intended_plan_sha256.clone(),
        consent_binding_sha256: state.consent_binding_sha256.clone(),
        confirmation_token_sha256: state.confirmation_token_sha256.clone(),
        normalized_target_sha256: state.normalized_target_sha256.clone(),
        requested_change_sha256: state.requested_change_sha256.clone(),
        reason_sha256: state.reason_sha256.clone(),
        operation_id_sha256: state.operation_id_sha256.clone(),
        execution_attempt_id_sha256: state.execution_attempt_id_sha256.clone(),
        provider_request_id_sha256: state.provider_request_id_sha256.clone(),
        attempt_binding_sha256: state.attempt_binding_sha256.clone(),
        state_sha256: hash_bytes(&state_bytes),
        state_size_bytes: state_bytes.len(),
        state_byte_cap: D1_DML_ATTEMPT_STATE_BYTE_CAP,
        provider_calls: 0,
        provider_mutations: 0,
        automatic_retry_permitted: false,
    };
    Ok(D1TargetWidePreparedProduct {
        receipt,
        state_bytes,
    })
}

fn canonical_state_bytes(
    state: &D1TargetWideAttemptState,
) -> Result<Vec<u8>, D1TargetWidePreparedError> {
    let mut bytes =
        serde_json::to_vec(state).expect("target-wide state serialization is infallible");
    bytes.push(b'\n');
    if bytes.len() > D1_DML_ATTEMPT_STATE_BYTE_CAP {
        return Err(prepared_error(
            D1TargetWidePreparedClassification::StateLimitExceeded,
            "canonical target-wide attempt state exceeded the exact byte cap",
        ));
    }
    Ok(bytes)
}

fn prepared_error(
    classification: D1TargetWidePreparedClassification,
    message: &'static str,
) -> D1TargetWidePreparedError {
    D1TargetWidePreparedError {
        code: "d1.target_wide_prepared_custody_unproven",
        classification,
        message,
    }
}

fn prepared_error_result(error: D1TargetWidePreparedError) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": D1_TARGET_WIDE_ATTEMPT_CUSTODY_OPERATION,
        "status": "reconciliation_required",
        "provider_calls": 0,
        "provider_mutations": 0,
        "automatic_retry_permitted": false,
        "error": {"code": error.code, "classification": error.classification, "message": error.message,
            "hint": "Retain exact local custody and resolve the Prepared boundary before any provider operation."}
    }))
}

fn target_wide_claimant_error_result(
    plan: &D1TargetWideIntendedPlan,
    code: &str,
    message: &str,
    phase: &str,
) -> CallToolResult {
    let code = match code {
        "d1.dml_identity_claimant_custody_unproven" => {
            "d1.target_wide_identity_claimant_custody_unproven"
        }
        "d1.dml_identity_claimant_conflict" => "d1.target_wide_identity_claimant_conflict",
        _ => code,
    };
    let phase = match phase {
        "pre_catalog_claimant_inspection" => "pending_claimant_inspection",
        "pre_catalog_claimant_conflict" => "pending_claimant_conflict",
        "pre_catalog_claimant_install" => "pending_claimant_install",
        "pre_catalog_claimant_readback" => "pending_claimant_readback",
        "post_catalog_claimant_inspection" => "bound_claimant_inspection",
        "post_catalog_claimant_conflict" => "bound_claimant_conflict",
        "post_catalog_claimant_seal" => "bound_claimant_seal",
        "post_catalog_claimant_readback" => "bound_claimant_readback",
        _ => phase,
    };
    let message = if message == "provider dispatch requires three exact Bound identity claimants" {
        "target-wide Prepared custody requires three exact Bound identity claimants"
    } else {
        message
    };
    claimant_error_result(plan, code, message, phase)
}

fn claimant_error_result(
    plan: &D1TargetWideIntendedPlan,
    code: &str,
    message: &str,
    phase: &str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": plan.plan.operation,
        "status": "reconciliation_required",
        "provider_calls": 0,
        "provider_mutations": 0,
        "automatic_retry_permitted": false,
        "custody": {"phase": phase, "retained": true},
        "error": {"code": code, "message": message,
            "hint": "Do not issue a provider operation; reconcile the exact durable identity claimant set."}
    }))
}

fn prepared_store_error(
    plan: &D1TargetWideIntendedPlan,
    code: &'static str,
    message: &'static str,
    phase: &'static str,
) -> CallToolResult {
    claimant_error_result(plan, code, message, phase)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn hash_serialized<T: Serialize + ?Sized>(value: &T) -> String {
    hash_bytes(&serde_json::to_vec(value).expect("custody evidence serialization is infallible"))
}

fn hash_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests;
