//! Pure terminal-eligibility derivation for one retained target-wide attempt.
//!
//! This boundary consumes only the exact, already-retained provider lifecycle
//! and effect evidence. It never reads or writes custody, consults current
//! target state, calls a provider, or installs terminal authority. In
//! particular, a matching non-causal observation from
//! `d1_target_wide_observation` is deliberately not an input.

use mcp_toolkit_core::response_contract::MutationApplyStatus;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::cloudflare::d1_database_mutation::D1DatabaseMutationLifecycle;
use crate::d1_dml_attempt_custody::{D1DmlAttemptIdentities, D1DmlAttemptPhase};
use crate::d1_target::D1TargetIdentity;
use crate::d1_target_wide_attempt_custody::{
    D1TargetWidePostProviderOutcome, D1TargetWidePreparedProduct,
    restore_bound_d1_target_wide_attempt,
};
use crate::d1_target_wide_mutation::D1TargetWideIntendedPlan;

const TERMINAL_ELIGIBILITY_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1TargetWideTerminalOutcome {
    Applied,
    NotApplied,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1TargetWideTerminalEligibilityStatus {
    Eligible,
    ReconciliationRequired,
}

/// A pure decision product for the later CAS boundary. `Eligible` means only
/// that retained causal provider evidence already proves the outcome; this
/// value grants no persistence or terminalization authority by itself.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWideTerminalEligibility {
    pub(crate) version: u8,
    pub(crate) status: D1TargetWideTerminalEligibilityStatus,
    pub(crate) outcome: Option<D1TargetWideTerminalOutcome>,
    pub(crate) target_key_sha256: String,
    pub(crate) intended_plan_sha256: String,
    pub(crate) consent_binding_sha256: String,
    pub(crate) consent_version: u8,
    pub(crate) operation_version: u8,
    pub(crate) operation_id_sha256: String,
    pub(crate) execution_attempt_id_sha256: String,
    pub(crate) provider_request_id_sha256: String,
    pub(crate) custody_generation_sha256: String,
    pub(crate) attempt_binding_sha256: String,
    pub(crate) incumbent_provider_evidence_sha256: String,
    pub(crate) provider_lifecycle_sha256: Option<String>,
    pub(crate) provider_response_body_sha256: Option<String>,
    pub(crate) provider_response_body_size_bytes: Option<usize>,
    pub(crate) provider_error_sha256: Option<String>,
    pub(crate) outcome_evidence_sha256: Option<String>,
    pub(crate) terminalization_authorized: bool,
    pub(crate) local_mutations: u8,
    pub(crate) provider_calls: u8,
    pub(crate) provider_mutations: Option<u8>,
    pub(crate) reason: &'static str,
}

/// Re-derive terminal eligibility from one exact retained attempt. The
/// confirmation token and identities are checked by the same pure restore
/// path that created custody; no caller-supplied stored digest is trusted.
pub(crate) fn derive_d1_target_wide_terminal_eligibility(
    target: &D1TargetIdentity,
    intended_plan: &D1TargetWideIntendedPlan,
    confirmation_token: &str,
    identities: D1DmlAttemptIdentities<'_>,
    incumbent: &D1TargetWidePreparedProduct,
) -> D1TargetWideTerminalEligibility {
    let receipt = incumbent.receipt();
    let identity_hashes = identity_hashes(identities);
    let base = |status, outcome, reason, restored: Option<&D1TargetWidePreparedProduct>| {
        let bound = restored.map_or(receipt, |product| product.receipt());
        D1TargetWideTerminalEligibility {
            version: TERMINAL_ELIGIBILITY_VERSION,
            status,
            outcome,
            target_key_sha256: target.target_key_sha256(),
            intended_plan_sha256: intended_plan.plan_sha256.clone(),
            consent_binding_sha256: hash_serialized(&intended_plan.consent_binding),
            consent_version: intended_plan.consent_binding.consent_version,
            operation_version: intended_plan.consent_binding.operation_version,
            operation_id_sha256: identity_hashes.0,
            execution_attempt_id_sha256: identity_hashes.1,
            provider_request_id_sha256: identity_hashes.2,
            custody_generation_sha256: bound.custody_generation_sha256.clone(),
            attempt_binding_sha256: bound.attempt_binding_sha256.clone(),
            incumbent_provider_evidence_sha256: incumbent_provider_evidence_sha256(bound),
            provider_lifecycle_sha256: bound.lifecycle_sha256.clone(),
            provider_response_body_sha256: bound.response_body_sha256.clone(),
            provider_response_body_size_bytes: bound.response_body_size_bytes,
            provider_error_sha256: bound.provider_error_sha256.clone(),
            outcome_evidence_sha256: None,
            terminalization_authorized: false,
            local_mutations: 0,
            provider_calls: bound.provider_calls,
            provider_mutations: bound.provider_mutations,
            reason,
        }
    };

    let restored = match restore_bound_d1_target_wide_attempt(
        target,
        intended_plan,
        confirmation_token,
        identities,
        incumbent.state_bytes(),
    ) {
        Ok(product) => product,
        Err(_) => {
            return base(
                D1TargetWideTerminalEligibilityStatus::ReconciliationRequired,
                None,
                "exact target, canonical consent, versions, identities, or retained state could not be rederived",
                None,
            );
        }
    };
    let receipt = restored.receipt();
    let mut decision = base(
        D1TargetWideTerminalEligibilityStatus::ReconciliationRequired,
        None,
        "retained provider evidence does not causally prove a terminal outcome",
        Some(&restored),
    );
    if receipt.phase != D1DmlAttemptPhase::ReconciliationRequired {
        decision.reason = "only retained post-provider evidence can establish terminal eligibility";
        return decision;
    }

    let eligible_outcome = match (
        receipt.post_provider_outcome,
        receipt.apply_status,
        receipt.provider_calls,
        receipt.provider_mutations,
        receipt.http_status,
        receipt.lifecycle_sha256.as_deref(),
        receipt.response_body_sha256.as_deref(),
        receipt.response_body_size_bytes,
        receipt.provider_error_sha256.as_deref(),
    ) {
        (
            Some(D1TargetWidePostProviderOutcome::Acknowledged),
            Some(MutationApplyStatus::Applied),
            1,
            Some(1),
            Some(status),
            Some(lifecycle),
            Some(response),
            Some(_),
            None,
        ) if (200..300).contains(&status)
            && lifecycle_matches(lifecycle, D1DatabaseMutationLifecycle::succeeded(status))
            && valid_sha256(response) =>
        {
            Some(D1TargetWideTerminalOutcome::Applied)
        }
        (
            Some(D1TargetWidePostProviderOutcome::ReconciliationRequired),
            Some(MutationApplyStatus::RejectedBeforeApply),
            0,
            Some(0),
            None,
            Some(lifecycle),
            None,
            None,
            Some(error),
        ) if lifecycle_matches(lifecycle, D1DatabaseMutationLifecycle::pre_dispatch())
            && valid_sha256(error) =>
        {
            Some(D1TargetWideTerminalOutcome::NotApplied)
        }
        _ => None,
    };
    let Some(outcome) = eligible_outcome else {
        return decision;
    };
    let outcome_evidence_sha256 = hash_serialized(&TerminalOutcomeMaterial {
        version: TERMINAL_ELIGIBILITY_VERSION,
        outcome,
        target_key_sha256: &decision.target_key_sha256,
        intended_plan_sha256: &decision.intended_plan_sha256,
        consent_binding_sha256: &decision.consent_binding_sha256,
        consent_version: decision.consent_version,
        operation_version: decision.operation_version,
        operation_id_sha256: &decision.operation_id_sha256,
        execution_attempt_id_sha256: &decision.execution_attempt_id_sha256,
        provider_request_id_sha256: &decision.provider_request_id_sha256,
        custody_generation_sha256: &decision.custody_generation_sha256,
        attempt_binding_sha256: &decision.attempt_binding_sha256,
        incumbent_provider_evidence_sha256: &decision.incumbent_provider_evidence_sha256,
        provider_lifecycle_sha256: decision.provider_lifecycle_sha256.as_deref(),
        provider_response_body_sha256: decision.provider_response_body_sha256.as_deref(),
        provider_response_body_size_bytes: decision.provider_response_body_size_bytes,
        provider_error_sha256: decision.provider_error_sha256.as_deref(),
    });
    decision.status = D1TargetWideTerminalEligibilityStatus::Eligible;
    decision.outcome = Some(outcome);
    decision.outcome_evidence_sha256 = Some(outcome_evidence_sha256);
    decision.reason =
        "retained provider lifecycle and effect evidence causally proves this outcome";
    decision.terminalization_authorized = false;
    decision
}

#[derive(Serialize)]
struct TerminalOutcomeMaterial<'a> {
    version: u8,
    outcome: D1TargetWideTerminalOutcome,
    target_key_sha256: &'a str,
    intended_plan_sha256: &'a str,
    consent_binding_sha256: &'a str,
    consent_version: u8,
    operation_version: u8,
    operation_id_sha256: &'a str,
    execution_attempt_id_sha256: &'a str,
    provider_request_id_sha256: &'a str,
    custody_generation_sha256: &'a str,
    attempt_binding_sha256: &'a str,
    incumbent_provider_evidence_sha256: &'a str,
    provider_lifecycle_sha256: Option<&'a str>,
    provider_response_body_sha256: Option<&'a str>,
    provider_response_body_size_bytes: Option<usize>,
    provider_error_sha256: Option<&'a str>,
}

fn identity_hashes(identities: D1DmlAttemptIdentities<'_>) -> (String, String, String) {
    (
        hash_bytes(identities.operation_id.as_bytes()),
        hash_bytes(identities.execution_attempt_id.as_bytes()),
        hash_bytes(identities.provider_request_id.as_bytes()),
    )
}

fn incumbent_provider_evidence_sha256(
    receipt: &crate::d1_target_wide_attempt_custody::D1TargetWidePreparedReceipt,
) -> String {
    hash_serialized(&(
        receipt.post_provider_outcome,
        receipt.apply_status,
        receipt.lifecycle_sha256.as_deref(),
        receipt.http_status,
        receipt.response_body_sha256.as_deref(),
        receipt.response_body_size_bytes,
        receipt.provider_error_sha256.as_deref(),
        receipt.provider_calls,
        receipt.provider_mutations,
    ))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn lifecycle_matches(stored_sha256: &str, expected: D1DatabaseMutationLifecycle) -> bool {
    valid_sha256(stored_sha256) && stored_sha256 == hash_serialized(&expected)
}

fn hash_serialized<T: Serialize + ?Sized>(value: &T) -> String {
    hash_bytes(&serde_json::to_vec(value).expect("terminal evidence serialization is infallible"))
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare::d1_database_mutation::D1DatabaseMutationLifecycle;
    use crate::d1_dml_attempt_custody::{D1DmlAttemptIdentities, TEST_CUSTODY_GENERATION_SHA256};
    use crate::d1_target::normalize_d1_target;
    use crate::d1_target_wide_attempt_custody::{
        inspect_d1_target_wide_attempt_state, prepare_d1_target_wide_attempt,
        prepare_d1_target_wide_dispatch_reservation_cas, record_d1_target_wide_acknowledgement,
        record_d1_target_wide_reconciliation_required,
    };
    use crate::d1_target_wide_mutation::rederive_d1_target_wide_intended_plan;
    use serde_json::json;

    const DATABASE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn ids() -> D1DmlAttemptIdentities<'static> {
        D1DmlAttemptIdentities {
            operation_id: "eligibility-operation-0001",
            execution_attempt_id: "eligibility-attempt-0001",
            provider_request_id: "eligibility-provider-0001",
            custody_generation_sha256: TEST_CUSTODY_GENERATION_SHA256,
        }
    }

    fn fixture() -> (
        D1TargetIdentity,
        D1TargetWideIntendedPlan,
        D1TargetWidePreparedProduct,
    ) {
        let target = normalize_d1_target("acct-1", DATABASE_ID).expect("target");
        let plan = rederive_d1_target_wide_intended_plan(
            &target,
            "d1_rename_database",
            &json!({"new_name": "renamed-db"}),
            Some("synthetic eligibility reason"),
        )
        .expect("plan");
        let prepared =
            prepare_d1_target_wide_attempt(&target, &plan, &plan.confirmation_token(), ids(), None)
                .expect("prepared");
        let reserved = prepare_d1_target_wide_dispatch_reservation_cas(
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            prepared.state_bytes(),
        )
        .expect("reserved");
        (target, plan, reserved)
    }

    #[test]
    fn acknowledged_provider_effect_is_eligible_applied_and_fully_rederived() {
        let (target, plan, reserved) = fixture();
        let causal = record_d1_target_wide_acknowledgement(
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            reserved.state_bytes(),
            D1DatabaseMutationLifecycle::succeeded(200),
            &hash_bytes(b"provider-success"),
            17,
        )
        .expect("acknowledged causal product");
        let eligibility = derive_d1_target_wide_terminal_eligibility(
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            &causal,
        );
        assert_eq!(
            eligibility.status,
            D1TargetWideTerminalEligibilityStatus::Eligible
        );
        assert_eq!(
            eligibility.outcome,
            Some(D1TargetWideTerminalOutcome::Applied)
        );
        assert!(!eligibility.terminalization_authorized);
        assert_eq!(eligibility.local_mutations, 0);
        assert_eq!(eligibility.provider_calls, 1);
        assert_eq!(eligibility.provider_mutations, Some(1));
        assert!(eligibility.outcome_evidence_sha256.is_some());
    }

    #[test]
    fn rejected_before_apply_is_eligible_not_applied_without_current_state() {
        let (target, plan, reserved) = fixture();
        let causal = record_d1_target_wide_reconciliation_required(
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            reserved.state_bytes(),
            D1DatabaseMutationLifecycle::pre_dispatch(),
            None,
            None,
            "cloudflare.d1.rejected_before_dispatch",
        )
        .expect("rejected causal product");
        let eligibility = derive_d1_target_wide_terminal_eligibility(
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            &causal,
        );
        assert_eq!(
            eligibility.status,
            D1TargetWideTerminalEligibilityStatus::Eligible
        );
        assert_eq!(
            eligibility.outcome,
            Some(D1TargetWideTerminalOutcome::NotApplied)
        );
        assert_eq!(eligibility.provider_calls, 0);
        assert_eq!(eligibility.provider_mutations, Some(0));
    }

    #[test]
    fn noncausal_observation_and_uncertain_effect_remain_reconciliation_required() {
        let (target, plan, reserved) = fixture();
        let uncertain = record_d1_target_wide_reconciliation_required(
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            reserved.state_bytes(),
            D1DatabaseMutationLifecycle::attempted_without_response(),
            None,
            None,
            "cloudflare.transport_error",
        )
        .expect("uncertain product");
        let eligibility = derive_d1_target_wide_terminal_eligibility(
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            &uncertain,
        );
        assert_eq!(
            eligibility.status,
            D1TargetWideTerminalEligibilityStatus::ReconciliationRequired
        );
        assert_eq!(eligibility.outcome, None);
        assert!(!eligibility.terminalization_authorized);
        assert_eq!(eligibility.local_mutations, 0);
    }

    #[test]
    fn dispatch_reserved_without_effect_and_wrong_context_are_ineligible() {
        let (target, plan, reserved) = fixture();
        let eligibility = derive_d1_target_wide_terminal_eligibility(
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            &reserved,
        );
        assert_eq!(eligibility.outcome, None);
        assert_eq!(
            eligibility.status,
            D1TargetWideTerminalEligibilityStatus::ReconciliationRequired
        );

        let mut wrong_ids = ids();
        wrong_ids.operation_id = "eligibility-operation-0002";
        let wrong = derive_d1_target_wide_terminal_eligibility(
            &target,
            &plan,
            &plan.confirmation_token(),
            wrong_ids,
            &reserved,
        );
        assert_eq!(wrong.outcome, None);
        assert_eq!(
            wrong.status,
            D1TargetWideTerminalEligibilityStatus::ReconciliationRequired
        );
    }

    #[test]
    fn contradictory_lifecycle_digest_cannot_become_eligible() {
        let (target, plan, reserved) = fixture();
        let causal = record_d1_target_wide_acknowledgement(
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            reserved.state_bytes(),
            D1DatabaseMutationLifecycle::succeeded(200),
            &hash_bytes(b"provider-success"),
            17,
        )
        .expect("acknowledged causal product");
        let lifecycle_sha256 = hash_serialized(&D1DatabaseMutationLifecycle::succeeded(200));
        let state = std::str::from_utf8(causal.state_bytes()).expect("canonical state");
        let contradictory = state.replacen(&lifecycle_sha256, &"0".repeat(64), 1);
        let bytes = contradictory.into_bytes();
        let contradictory = inspect_d1_target_wide_attempt_state(&bytes)
            .expect("stored lifecycle shape remains canonical");
        let eligibility = derive_d1_target_wide_terminal_eligibility(
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            &contradictory,
        );
        assert_eq!(
            eligibility.status,
            D1TargetWideTerminalEligibilityStatus::ReconciliationRequired
        );
        assert_eq!(eligibility.outcome, None);
        assert!(eligibility.outcome_evidence_sha256.is_none());
    }
}
