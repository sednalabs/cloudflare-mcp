//! Recoverable bounded custody for one exact D1 DML execution attempt.
//!
//! This pure state machine consumes the opaque exact-plan composition product,
//! hashes three preallocated opaque identities, and emits one canonical private
//! state artifact. Only the `Prepared -> DispatchCrossed` transition authorizes
//! crossing a provider dispatch boundary, exactly once. Every later replay is
//! non-authorizing. Ambiguous transport or response evidence is retained as
//! `ReconciliationRequired` and can never authorize automatic redispatch.
//!
//! Provider terminal evidence and independent readback evidence occupy separate
//! typed slots. Custody reaches a terminal outcome only when both are present
//! and compatible. This module performs no persistence, provider request,
//! readback, public routing, admission, retry, deployment, or configuration.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::d1_exact_plan_composition::{
    D1_EXACT_PLAN_COMPOSITION_OPERATION, D1ExactPlanCompositionProduct,
};
use crate::d1_target::{D1TargetIdentity, normalize_d1_target};

pub(crate) const D1_DML_ATTEMPT_CUSTODY_OPERATION: &str = "d1_dml_attempt_custody";

const CUSTODY_VERSION: u8 = 1;
const REQUIRED_COMPOSITION_VERSION: u8 = 1;
const MAX_OPAQUE_IDENTITY_BYTES: usize = 128;
const MIN_OPAQUE_IDENTITY_BYTES: usize = 16;
pub(crate) const D1_DML_ATTEMPT_STATE_BYTE_CAP: usize = 16 * 1024;

#[derive(Debug, Clone, Copy)]
pub(crate) struct D1DmlAttemptIdentities<'a> {
    pub(crate) operation_id: &'a str,
    pub(crate) execution_attempt_id: &'a str,
    pub(crate) provider_request_id: &'a str,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlAttemptPhase {
    Prepared,
    DispatchCrossed,
    ReconciliationRequired,
    TerminalApplied,
    TerminalNotApplied,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlAttemptAmbiguity {
    DispatchReplay,
    TransportUncertain,
    ResponseMissing,
    ResponseIncomplete,
    ResponseMalformed,
    ResponseContradictory,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlProviderTerminalClassification {
    SucceededChanged,
    SucceededUnchanged,
    RejectedTerminal,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct D1DmlProviderTerminalInput<'a> {
    pub(crate) classification: D1DmlProviderTerminalClassification,
    pub(crate) evidence_sha256: &'a str,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlReadbackTerminalClassification {
    ExpectedStateObserved,
    ExpectedStateAbsent,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct D1DmlReadbackTerminalInput<'a> {
    pub(crate) classification: D1DmlReadbackTerminalClassification,
    pub(crate) readback_plan_sha256: &'a str,
    pub(crate) evidence_sha256: &'a str,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct D1DmlProviderTerminalEvidence {
    version: u8,
    attempt_binding_sha256: String,
    provider_request_id_sha256: String,
    classification: D1DmlProviderTerminalClassification,
    evidence_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct D1DmlReadbackTerminalEvidence {
    version: u8,
    attempt_binding_sha256: String,
    classification: D1DmlReadbackTerminalClassification,
    readback_plan_sha256: String,
    evidence_sha256: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlAttemptTerminalOutcome {
    Applied,
    NotApplied,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct D1DmlAttemptState {
    version: u8,
    operation: String,
    target_key_sha256: String,
    execute_plan_sha256: String,
    composition_sha256: String,
    composition_receipt_sha256: String,
    operation_id_sha256: String,
    execution_attempt_id_sha256: String,
    provider_request_id_sha256: String,
    attempt_binding_sha256: String,
    phase: D1DmlAttemptPhase,
    dispatch_crossings: u8,
    ambiguity: Option<D1DmlAttemptAmbiguity>,
    provider_evidence: Option<D1DmlProviderTerminalEvidence>,
    readback_evidence: Option<D1DmlReadbackTerminalEvidence>,
    terminal_outcome: Option<D1DmlAttemptTerminalOutcome>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlAttemptTransition {
    Prepared,
    ExactReplay,
    DispatchBoundaryCrossed,
    DispatchReplayQuarantined,
    AmbiguityRecorded,
    ProviderEvidenceRecorded,
    ProviderEvidenceReplay,
    ReadbackEvidenceRecorded,
    ReadbackEvidenceReplay,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlAttemptRetryDecision {
    DispatchNotYetCrossed,
    DoNotRedispatchSameAttempt,
    TerminalReplayOnly,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1DmlAttemptCustodyReceipt {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) phase: D1DmlAttemptPhase,
    pub(crate) transition: D1DmlAttemptTransition,
    pub(crate) retry_decision: D1DmlAttemptRetryDecision,
    pub(crate) target_key_sha256: String,
    pub(crate) execute_plan_sha256: String,
    pub(crate) composition_sha256: String,
    pub(crate) composition_receipt_sha256: String,
    pub(crate) operation_id_sha256: String,
    pub(crate) execution_attempt_id_sha256: String,
    pub(crate) provider_request_id_sha256: String,
    pub(crate) attempt_binding_sha256: String,
    pub(crate) state_sha256: String,
    pub(crate) state_size_bytes: usize,
    pub(crate) state_byte_cap: usize,
    pub(crate) dispatch_crossings: u8,
    pub(crate) dispatch_authorized_this_transition: bool,
    pub(crate) exact_replay: bool,
    pub(crate) ambiguity: Option<D1DmlAttemptAmbiguity>,
    pub(crate) provider_evidence_present: bool,
    pub(crate) provider_evidence_sha256: Option<String>,
    pub(crate) readback_evidence_present: bool,
    pub(crate) readback_evidence_sha256: Option<String>,
    pub(crate) terminal_outcome: Option<D1DmlAttemptTerminalOutcome>,
}

/// Opaque pure custody product. The canonical state bytes are private durable
/// material for a later persistence boundary; the receipt is aggregate-safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1DmlAttemptCustodyProduct {
    receipt: D1DmlAttemptCustodyReceipt,
    state_bytes: Vec<u8>,
}

impl D1DmlAttemptCustodyProduct {
    pub(crate) fn receipt(&self) -> &D1DmlAttemptCustodyReceipt {
        &self.receipt
    }

    pub(crate) fn state_bytes(&self) -> &[u8] {
        &self.state_bytes
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlAttemptCustodyClassification {
    TargetIdentityInvalid,
    CompositionProductMismatch,
    OpaqueIdentityInvalid,
    OpaqueIdentityDuplicate,
    RestoredStateRequired,
    RestoredStateTooLarge,
    RestoredStateMalformed,
    RestoredStateNonCanonical,
    RestoredStateUnsupported,
    RestoredStateContradictory,
    ReplayConflict,
    TransitionBeforeDispatch,
    AmbiguityConflict,
    EvidenceDigestInvalid,
    EvidenceConflict,
    StateLimitExceeded,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1DmlAttemptCustodyError {
    pub(crate) code: &'static str,
    pub(crate) classification: D1DmlAttemptCustodyClassification,
    pub(crate) message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct D1DmlAttemptBinding {
    target_key_sha256: String,
    execute_plan_sha256: String,
    composition_sha256: String,
    composition_receipt_sha256: String,
    operation_id_sha256: String,
    execution_attempt_id_sha256: String,
    provider_request_id_sha256: String,
    attempt_binding_sha256: String,
}

pub(crate) fn prepare_d1_dml_attempt(
    target: &D1TargetIdentity,
    composition: &D1ExactPlanCompositionProduct,
    identities: D1DmlAttemptIdentities<'_>,
    restored_state: Option<&[u8]>,
) -> Result<D1DmlAttemptCustodyProduct, D1DmlAttemptCustodyError> {
    let binding = derive_attempt_binding(target, composition, identities)?;
    match restored_state {
        None => {
            let state = D1DmlAttemptState {
                version: CUSTODY_VERSION,
                operation: D1_DML_ATTEMPT_CUSTODY_OPERATION.to_string(),
                target_key_sha256: binding.target_key_sha256.clone(),
                execute_plan_sha256: binding.execute_plan_sha256.clone(),
                composition_sha256: binding.composition_sha256.clone(),
                composition_receipt_sha256: binding.composition_receipt_sha256.clone(),
                operation_id_sha256: binding.operation_id_sha256.clone(),
                execution_attempt_id_sha256: binding.execution_attempt_id_sha256.clone(),
                provider_request_id_sha256: binding.provider_request_id_sha256.clone(),
                attempt_binding_sha256: binding.attempt_binding_sha256.clone(),
                phase: D1DmlAttemptPhase::Prepared,
                dispatch_crossings: 0,
                ambiguity: None,
                provider_evidence: None,
                readback_evidence: None,
                terminal_outcome: None,
            };
            product(state, D1DmlAttemptTransition::Prepared, false, false)
        }
        Some(bytes) => {
            let state = restore_exact_state(bytes, &binding)?;
            product(state, D1DmlAttemptTransition::ExactReplay, false, true)
        }
    }
}

pub(crate) fn cross_d1_dml_dispatch_boundary(
    target: &D1TargetIdentity,
    composition: &D1ExactPlanCompositionProduct,
    identities: D1DmlAttemptIdentities<'_>,
    restored_state: &[u8],
) -> Result<D1DmlAttemptCustodyProduct, D1DmlAttemptCustodyError> {
    let binding = derive_attempt_binding(target, composition, identities)?;
    let mut state = restore_exact_state(restored_state, &binding)?;
    match state.phase {
        D1DmlAttemptPhase::Prepared => {
            state.dispatch_crossings = 1;
            refresh_derived_state(&mut state)?;
            product(
                state,
                D1DmlAttemptTransition::DispatchBoundaryCrossed,
                true,
                false,
            )
        }
        D1DmlAttemptPhase::DispatchCrossed => {
            state.ambiguity = Some(D1DmlAttemptAmbiguity::DispatchReplay);
            refresh_derived_state(&mut state)?;
            product(
                state,
                D1DmlAttemptTransition::DispatchReplayQuarantined,
                false,
                true,
            )
        }
        D1DmlAttemptPhase::ReconciliationRequired
        | D1DmlAttemptPhase::TerminalApplied
        | D1DmlAttemptPhase::TerminalNotApplied => {
            product(state, D1DmlAttemptTransition::ExactReplay, false, true)
        }
    }
}

pub(crate) fn record_d1_dml_attempt_ambiguity(
    target: &D1TargetIdentity,
    composition: &D1ExactPlanCompositionProduct,
    identities: D1DmlAttemptIdentities<'_>,
    restored_state: &[u8],
    ambiguity: D1DmlAttemptAmbiguity,
) -> Result<D1DmlAttemptCustodyProduct, D1DmlAttemptCustodyError> {
    let binding = derive_attempt_binding(target, composition, identities)?;
    let mut state = restore_exact_state(restored_state, &binding)?;
    require_dispatch_crossed(&state)?;
    if state.terminal_outcome.is_some() {
        return product(state, D1DmlAttemptTransition::ExactReplay, false, true);
    }
    if let Some(incumbent) = state.ambiguity {
        if incumbent != ambiguity {
            return Err(custody_error(
                D1DmlAttemptCustodyClassification::AmbiguityConflict,
                "attempt ambiguity contradicted incumbent durable evidence",
            ));
        }
        return product(state, D1DmlAttemptTransition::ExactReplay, false, true);
    }
    state.ambiguity = Some(ambiguity);
    refresh_derived_state(&mut state)?;
    product(
        state,
        D1DmlAttemptTransition::AmbiguityRecorded,
        false,
        false,
    )
}

pub(crate) fn record_d1_dml_provider_terminal_evidence(
    target: &D1TargetIdentity,
    composition: &D1ExactPlanCompositionProduct,
    identities: D1DmlAttemptIdentities<'_>,
    restored_state: &[u8],
    evidence: D1DmlProviderTerminalInput<'_>,
) -> Result<D1DmlAttemptCustodyProduct, D1DmlAttemptCustodyError> {
    let binding = derive_attempt_binding(target, composition, identities)?;
    let mut state = restore_exact_state(restored_state, &binding)?;
    require_dispatch_crossed(&state)?;
    if !valid_sha256(evidence.evidence_sha256) {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::EvidenceDigestInvalid,
            "provider terminal evidence digest was not canonical SHA-256",
        ));
    }
    let candidate = D1DmlProviderTerminalEvidence {
        version: CUSTODY_VERSION,
        attempt_binding_sha256: binding.attempt_binding_sha256,
        provider_request_id_sha256: binding.provider_request_id_sha256,
        classification: evidence.classification,
        evidence_sha256: evidence.evidence_sha256.to_string(),
    };
    if let Some(incumbent) = &state.provider_evidence {
        if incumbent != &candidate {
            return Err(custody_error(
                D1DmlAttemptCustodyClassification::EvidenceConflict,
                "provider terminal evidence contradicted the incumbent product",
            ));
        }
        return product(
            state,
            D1DmlAttemptTransition::ProviderEvidenceReplay,
            false,
            true,
        );
    }
    state.provider_evidence = Some(candidate);
    refresh_derived_state(&mut state)?;
    product(
        state,
        D1DmlAttemptTransition::ProviderEvidenceRecorded,
        false,
        false,
    )
}

pub(crate) fn record_d1_dml_readback_terminal_evidence(
    target: &D1TargetIdentity,
    composition: &D1ExactPlanCompositionProduct,
    identities: D1DmlAttemptIdentities<'_>,
    restored_state: &[u8],
    evidence: D1DmlReadbackTerminalInput<'_>,
) -> Result<D1DmlAttemptCustodyProduct, D1DmlAttemptCustodyError> {
    let binding = derive_attempt_binding(target, composition, identities)?;
    let mut state = restore_exact_state(restored_state, &binding)?;
    require_dispatch_crossed(&state)?;
    if !valid_sha256(evidence.readback_plan_sha256) || !valid_sha256(evidence.evidence_sha256) {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::EvidenceDigestInvalid,
            "readback terminal evidence digests were not canonical SHA-256",
        ));
    }
    let candidate = D1DmlReadbackTerminalEvidence {
        version: CUSTODY_VERSION,
        attempt_binding_sha256: binding.attempt_binding_sha256,
        classification: evidence.classification,
        readback_plan_sha256: evidence.readback_plan_sha256.to_string(),
        evidence_sha256: evidence.evidence_sha256.to_string(),
    };
    if let Some(incumbent) = &state.readback_evidence {
        if incumbent != &candidate {
            return Err(custody_error(
                D1DmlAttemptCustodyClassification::EvidenceConflict,
                "readback terminal evidence contradicted the incumbent product",
            ));
        }
        return product(
            state,
            D1DmlAttemptTransition::ReadbackEvidenceReplay,
            false,
            true,
        );
    }
    state.readback_evidence = Some(candidate);
    refresh_derived_state(&mut state)?;
    product(
        state,
        D1DmlAttemptTransition::ReadbackEvidenceRecorded,
        false,
        false,
    )
}

fn derive_attempt_binding(
    target: &D1TargetIdentity,
    composition: &D1ExactPlanCompositionProduct,
    identities: D1DmlAttemptIdentities<'_>,
) -> Result<D1DmlAttemptBinding, D1DmlAttemptCustodyError> {
    let normalized =
        normalize_d1_target(&target.account_id, &target.database_id).map_err(|_| {
            custody_error(
                D1DmlAttemptCustodyClassification::TargetIdentityInvalid,
                "D1 target identity was not exact canonical input",
            )
        })?;
    if &normalized != target {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::TargetIdentityInvalid,
            "D1 target identity was not exact canonical input",
        ));
    }

    let receipt = composition.receipt();
    let plan = composition.plan();
    let target_key_sha256 = target.target_key_sha256();
    if receipt.version != REQUIRED_COMPOSITION_VERSION
        || receipt.operation != D1_EXACT_PLAN_COMPOSITION_OPERATION
        || receipt.target_key_sha256 != target_key_sha256
        || plan.account_id != target.account_id
        || plan.database_id != target.database_id
        || plan.target_key_sha256 != target_key_sha256
        || hash_serialized(plan) != receipt.execute_plan_sha256
        || receipt.effective_primitive_count != composition.effective_primitives().len()
        || receipt.allow_decision_count != receipt.effective_primitive_count
        || !composition_receipt_digests_are_valid(receipt)
    {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::CompositionProductMismatch,
            "exact DML composition contradicted the target or opaque product",
        ));
    }

    let opaque = [
        identities.operation_id,
        identities.execution_attempt_id,
        identities.provider_request_id,
    ];
    if opaque.iter().any(|value| !valid_opaque_identity(value)) {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::OpaqueIdentityInvalid,
            "preallocated attempt identities were not exact bounded opaque identifiers",
        ));
    }
    if opaque.into_iter().collect::<BTreeSet<_>>().len() != 3 {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::OpaqueIdentityDuplicate,
            "preallocated attempt identities were not pairwise distinct",
        ));
    }

    let operation_id_sha256 = hash_bytes(identities.operation_id.as_bytes());
    let execution_attempt_id_sha256 = hash_bytes(identities.execution_attempt_id.as_bytes());
    let provider_request_id_sha256 = hash_bytes(identities.provider_request_id.as_bytes());
    let composition_receipt_sha256 = hash_serialized(receipt);
    let attempt_binding_sha256 = hash_serialized(&(
        CUSTODY_VERSION,
        D1_DML_ATTEMPT_CUSTODY_OPERATION,
        target_key_sha256.as_str(),
        receipt.execute_plan_sha256.as_str(),
        receipt.composition_sha256.as_str(),
        composition_receipt_sha256.as_str(),
        operation_id_sha256.as_str(),
        execution_attempt_id_sha256.as_str(),
        provider_request_id_sha256.as_str(),
    ));
    Ok(D1DmlAttemptBinding {
        target_key_sha256,
        execute_plan_sha256: receipt.execute_plan_sha256.clone(),
        composition_sha256: receipt.composition_sha256.clone(),
        composition_receipt_sha256,
        operation_id_sha256,
        execution_attempt_id_sha256,
        provider_request_id_sha256,
        attempt_binding_sha256,
    })
}

fn restore_exact_state(
    bytes: &[u8],
    binding: &D1DmlAttemptBinding,
) -> Result<D1DmlAttemptState, D1DmlAttemptCustodyError> {
    if bytes.is_empty() {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::RestoredStateRequired,
            "one physically present attempt state artifact was required",
        ));
    }
    if bytes.len() > D1_DML_ATTEMPT_STATE_BYTE_CAP {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::RestoredStateTooLarge,
            "attempt state artifact exceeded the exact byte cap",
        ));
    }
    let state = serde_json::from_slice::<D1DmlAttemptState>(bytes).map_err(|_| {
        custody_error(
            D1DmlAttemptCustodyClassification::RestoredStateMalformed,
            "attempt state artifact was malformed or outside the closed schema",
        )
    })?;
    let canonical = canonical_state_bytes(&state)?;
    if canonical != bytes {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::RestoredStateNonCanonical,
            "attempt state artifact was not exact canonical JSON",
        ));
    }
    validate_state(&state)?;
    if !state_matches_binding(&state, binding) {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::ReplayConflict,
            "attempt replay contradicted the exact target, plan, composition, or identities",
        ));
    }
    Ok(state)
}

fn validate_state(state: &D1DmlAttemptState) -> Result<(), D1DmlAttemptCustodyError> {
    if state.version != CUSTODY_VERSION || state.operation != D1_DML_ATTEMPT_CUSTODY_OPERATION {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::RestoredStateUnsupported,
            "attempt state artifact version or operation was unsupported",
        ));
    }
    if !all_state_digests_are_valid(state) {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::RestoredStateContradictory,
            "attempt state artifact contained malformed digest evidence",
        ));
    }
    validate_provider_evidence(state)?;
    validate_readback_evidence(state)?;
    let (expected_phase, expected_terminal) = derive_phase_and_terminal(state)?;
    if state.phase != expected_phase || state.terminal_outcome != expected_terminal {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::RestoredStateContradictory,
            "attempt state phase contradicted its durable evidence",
        ));
    }
    Ok(())
}

fn refresh_derived_state(state: &mut D1DmlAttemptState) -> Result<(), D1DmlAttemptCustodyError> {
    let (phase, terminal) = derive_phase_and_terminal(state)?;
    state.phase = phase;
    state.terminal_outcome = terminal;
    validate_state(state)
}

fn derive_phase_and_terminal(
    state: &D1DmlAttemptState,
) -> Result<(D1DmlAttemptPhase, Option<D1DmlAttemptTerminalOutcome>), D1DmlAttemptCustodyError> {
    if state.dispatch_crossings > 1 {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::RestoredStateContradictory,
            "attempt state claimed more than one dispatch-boundary crossing",
        ));
    }
    if state.dispatch_crossings == 0 {
        if state.ambiguity.is_some()
            || state.provider_evidence.is_some()
            || state.readback_evidence.is_some()
            || state.terminal_outcome.is_some()
        {
            return Err(custody_error(
                D1DmlAttemptCustodyClassification::RestoredStateContradictory,
                "predispatch attempt state contained post-dispatch evidence",
            ));
        }
        return Ok((D1DmlAttemptPhase::Prepared, None));
    }

    let evidence_outcome = match (&state.provider_evidence, &state.readback_evidence) {
        (Some(provider), Some(readback)) => {
            match (provider.classification, readback.classification) {
                (
                    D1DmlProviderTerminalClassification::SucceededChanged
                    | D1DmlProviderTerminalClassification::SucceededUnchanged,
                    D1DmlReadbackTerminalClassification::ExpectedStateObserved,
                ) => Some(D1DmlAttemptTerminalOutcome::Applied),
                (
                    D1DmlProviderTerminalClassification::RejectedTerminal,
                    D1DmlReadbackTerminalClassification::ExpectedStateAbsent,
                ) => Some(D1DmlAttemptTerminalOutcome::NotApplied),
                _ => None,
            }
        }
        _ => None,
    };
    let contradictory_pair = state.provider_evidence.is_some()
        && state.readback_evidence.is_some()
        && evidence_outcome.is_none();
    let phase = match evidence_outcome {
        Some(D1DmlAttemptTerminalOutcome::Applied) => D1DmlAttemptPhase::TerminalApplied,
        Some(D1DmlAttemptTerminalOutcome::NotApplied) => D1DmlAttemptPhase::TerminalNotApplied,
        None if state.ambiguity.is_some() || contradictory_pair => {
            D1DmlAttemptPhase::ReconciliationRequired
        }
        None => D1DmlAttemptPhase::DispatchCrossed,
    };
    Ok((phase, evidence_outcome))
}

fn validate_provider_evidence(state: &D1DmlAttemptState) -> Result<(), D1DmlAttemptCustodyError> {
    if let Some(evidence) = &state.provider_evidence
        && (evidence.version != CUSTODY_VERSION
            || evidence.attempt_binding_sha256 != state.attempt_binding_sha256
            || evidence.provider_request_id_sha256 != state.provider_request_id_sha256
            || !valid_sha256(&evidence.evidence_sha256))
    {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::RestoredStateContradictory,
            "provider terminal evidence contradicted attempt custody",
        ));
    }
    Ok(())
}

fn validate_readback_evidence(state: &D1DmlAttemptState) -> Result<(), D1DmlAttemptCustodyError> {
    if let Some(evidence) = &state.readback_evidence
        && (evidence.version != CUSTODY_VERSION
            || evidence.attempt_binding_sha256 != state.attempt_binding_sha256
            || !valid_sha256(&evidence.readback_plan_sha256)
            || !valid_sha256(&evidence.evidence_sha256))
    {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::RestoredStateContradictory,
            "readback terminal evidence contradicted attempt custody",
        ));
    }
    Ok(())
}

fn require_dispatch_crossed(state: &D1DmlAttemptState) -> Result<(), D1DmlAttemptCustodyError> {
    if state.dispatch_crossings != 1 {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::TransitionBeforeDispatch,
            "post-dispatch evidence cannot precede the durable dispatch crossing",
        ));
    }
    Ok(())
}

fn product(
    state: D1DmlAttemptState,
    transition: D1DmlAttemptTransition,
    dispatch_authorized_this_transition: bool,
    exact_replay: bool,
) -> Result<D1DmlAttemptCustodyProduct, D1DmlAttemptCustodyError> {
    validate_state(&state)?;
    let state_bytes = canonical_state_bytes(&state)?;
    let retry_decision = match state.phase {
        D1DmlAttemptPhase::Prepared => D1DmlAttemptRetryDecision::DispatchNotYetCrossed,
        D1DmlAttemptPhase::DispatchCrossed | D1DmlAttemptPhase::ReconciliationRequired => {
            D1DmlAttemptRetryDecision::DoNotRedispatchSameAttempt
        }
        D1DmlAttemptPhase::TerminalApplied | D1DmlAttemptPhase::TerminalNotApplied => {
            D1DmlAttemptRetryDecision::TerminalReplayOnly
        }
    };
    let receipt = D1DmlAttemptCustodyReceipt {
        version: CUSTODY_VERSION,
        operation: D1_DML_ATTEMPT_CUSTODY_OPERATION,
        phase: state.phase,
        transition,
        retry_decision,
        target_key_sha256: state.target_key_sha256.clone(),
        execute_plan_sha256: state.execute_plan_sha256.clone(),
        composition_sha256: state.composition_sha256.clone(),
        composition_receipt_sha256: state.composition_receipt_sha256.clone(),
        operation_id_sha256: state.operation_id_sha256.clone(),
        execution_attempt_id_sha256: state.execution_attempt_id_sha256.clone(),
        provider_request_id_sha256: state.provider_request_id_sha256.clone(),
        attempt_binding_sha256: state.attempt_binding_sha256.clone(),
        state_sha256: hash_bytes(&state_bytes),
        state_size_bytes: state_bytes.len(),
        state_byte_cap: D1_DML_ATTEMPT_STATE_BYTE_CAP,
        dispatch_crossings: state.dispatch_crossings,
        dispatch_authorized_this_transition,
        exact_replay,
        ambiguity: state.ambiguity,
        provider_evidence_present: state.provider_evidence.is_some(),
        provider_evidence_sha256: state.provider_evidence.as_ref().map(hash_serialized),
        readback_evidence_present: state.readback_evidence.is_some(),
        readback_evidence_sha256: state.readback_evidence.as_ref().map(hash_serialized),
        terminal_outcome: state.terminal_outcome,
    };
    Ok(D1DmlAttemptCustodyProduct {
        receipt,
        state_bytes,
    })
}

fn canonical_state_bytes(state: &D1DmlAttemptState) -> Result<Vec<u8>, D1DmlAttemptCustodyError> {
    let mut bytes = serde_json::to_vec(state).expect("attempt state serialization is infallible");
    bytes.push(b'\n');
    if bytes.len() > D1_DML_ATTEMPT_STATE_BYTE_CAP {
        return Err(custody_error(
            D1DmlAttemptCustodyClassification::StateLimitExceeded,
            "canonical attempt state exceeded the exact byte cap",
        ));
    }
    Ok(bytes)
}

fn state_matches_binding(state: &D1DmlAttemptState, binding: &D1DmlAttemptBinding) -> bool {
    state.target_key_sha256 == binding.target_key_sha256
        && state.execute_plan_sha256 == binding.execute_plan_sha256
        && state.composition_sha256 == binding.composition_sha256
        && state.composition_receipt_sha256 == binding.composition_receipt_sha256
        && state.operation_id_sha256 == binding.operation_id_sha256
        && state.execution_attempt_id_sha256 == binding.execution_attempt_id_sha256
        && state.provider_request_id_sha256 == binding.provider_request_id_sha256
        && state.attempt_binding_sha256 == binding.attempt_binding_sha256
}

fn composition_receipt_digests_are_valid(
    receipt: &crate::d1_exact_plan_composition::D1ExactPlanCompositionReceipt,
) -> bool {
    [
        &receipt.target_key_sha256,
        &receipt.execute_plan_sha256,
        &receipt.catalog_snapshot_sha256,
        &receipt.catalog_receipt_sha256,
        &receipt.graph_sha256,
        &receipt.graph_decision_sha256,
        &receipt.graph_receipt_sha256,
        &receipt.classified_relation_sha256,
        &receipt.classified_form_sha256,
        &receipt.effective_primitive_sha256,
        &receipt.effective_decision_sha256,
        &receipt.composition_sha256,
    ]
    .into_iter()
    .all(|value| valid_sha256(value))
}

fn all_state_digests_are_valid(state: &D1DmlAttemptState) -> bool {
    [
        &state.target_key_sha256,
        &state.execute_plan_sha256,
        &state.composition_sha256,
        &state.composition_receipt_sha256,
        &state.operation_id_sha256,
        &state.execution_attempt_id_sha256,
        &state.provider_request_id_sha256,
        &state.attempt_binding_sha256,
    ]
    .into_iter()
    .all(|value| valid_sha256(value))
}

fn valid_opaque_identity(value: &str) -> bool {
    (MIN_OPAQUE_IDENTITY_BYTES..=MAX_OPAQUE_IDENTITY_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn custody_error(
    classification: D1DmlAttemptCustodyClassification,
    message: &'static str,
) -> D1DmlAttemptCustodyError {
    D1DmlAttemptCustodyError {
        code: "d1.dml_attempt_custody_unproven",
        classification,
        message,
    }
}

fn hash_serialized<T: Serialize + ?Sized>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("custody evidence serialization is infallible");
    hash_bytes(&bytes)
}

fn hash_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests;
