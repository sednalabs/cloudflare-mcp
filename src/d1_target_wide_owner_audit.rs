//! Owner-aware complete-audit authority for one canonical target-wide Prepared attempt.
//!
//! This D1-specific boundary accepts exactly one unresolved Prepared owner in an
//! otherwise complete and terminal custody graph. It authorizes only the later
//! local `Prepared -> DispatchReserved` compare-and-exchange. It performs no
//! persistence or provider operation and grants no provider-dispatch authority.

use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::d1_dml_attempt_custody::{D1DmlAttemptIdentities, D1DmlAttemptPhase};
use crate::d1_dml_custody_layout::{
    D1DmlCustodyAuditProviderAuthority, D1DmlCustodyCompleteAuditReceipt,
};
use crate::d1_dml_identity_claimant::{
    D1DmlIdentityClaimantPhase, D1DmlIdentityNamespace, derive_d1_dml_identity_claimant_set,
};
use crate::d1_migration_lease::D1TargetMutationGuard;
use crate::d1_target::D1TargetIdentity;
use crate::d1_target_wide_attempt_custody::{
    D1TargetWidePreparedProduct, prepare_d1_target_wide_attempt,
};
use crate::d1_target_wide_mutation::D1TargetWideIntendedPlan;

pub(crate) const D1_TARGET_WIDE_OWNER_AUDIT_OPERATION: &str = "d1_target_wide_prepared_owner_audit";
const OWNER_AUDIT_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1TargetWideOwnerAuthorizationScope {
    DispatchReservationOnly,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWidePreparedOwnerAuthorization {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) consent_version: u8,
    pub(crate) operation_version: u8,
    pub(crate) target_operation: String,
    pub(crate) phase: D1DmlAttemptPhase,
    pub(crate) authorization_scope: D1TargetWideOwnerAuthorizationScope,
    pub(crate) target_key_sha256: String,
    pub(crate) intended_plan_sha256: String,
    pub(crate) consent_binding_sha256: String,
    pub(crate) confirmation_token_sha256: String,
    pub(crate) operation_id_sha256: String,
    pub(crate) execution_attempt_id_sha256: String,
    pub(crate) provider_request_id_sha256: String,
    pub(crate) attempt_binding_sha256: String,
    pub(crate) claimant_set_sha256: String,
    pub(crate) complete_audit_sha256: String,
    pub(crate) complete_audit_attempt_count: usize,
    pub(crate) surrounding_terminal_attempt_count: usize,
    pub(crate) provider_dispatch_authority: D1DmlCustodyAuditProviderAuthority,
    pub(crate) provider_calls: u8,
    pub(crate) provider_mutations: u8,
    pub(crate) local_mutations: u8,
    pub(crate) authorization_sha256: String,
}

#[derive(Serialize)]
struct OwnerAuthorizationMaterial<'a> {
    version: u8,
    operation: &'a str,
    consent_version: u8,
    operation_version: u8,
    target_operation: &'a str,
    phase: D1DmlAttemptPhase,
    authorization_scope: D1TargetWideOwnerAuthorizationScope,
    target_key_sha256: &'a str,
    intended_plan_sha256: &'a str,
    consent_binding_sha256: &'a str,
    confirmation_token_sha256: &'a str,
    operation_id_sha256: &'a str,
    execution_attempt_id_sha256: &'a str,
    provider_request_id_sha256: &'a str,
    attempt_binding_sha256: &'a str,
    claimant_set_sha256: &'a str,
    complete_audit_sha256: &'a str,
    complete_audit_attempt_count: usize,
    surrounding_terminal_attempt_count: usize,
    provider_dispatch_authority: D1DmlCustodyAuditProviderAuthority,
    provider_calls: u8,
    provider_mutations: u8,
    local_mutations: u8,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1TargetWideOwnerAuditClassification {
    PreparedProductInvalid,
    CompleteAuditUnavailable,
    CompleteAuditContradictory,
    OwnerAttemptMissingOrConflicting,
    OwnerClaimantsMissingOrConflicting,
    CustodyChanged,
    AuthorizationChanged,
}

/// Derive the smallest owner-aware authorization product from a stable,
/// complete target-wide audit plus exact physical owner readback.
pub(crate) fn authorize_d1_target_wide_prepared_owner(
    guard: &D1TargetMutationGuard,
    target: &D1TargetIdentity,
    intended_plan: &D1TargetWideIntendedPlan,
    confirmation_token: &str,
    identities: D1DmlAttemptIdentities<'_>,
    prepared: &D1TargetWidePreparedProduct,
) -> Result<D1TargetWidePreparedOwnerAuthorization, CallToolResult> {
    guard.assert_exact_target(target).map_err(|_| {
        owner_error(
            D1TargetWideOwnerAuditClassification::PreparedProductInvalid,
            "target and held mutation authority were not exact",
        )
    })?;
    let expected =
        prepare_d1_target_wide_attempt(target, intended_plan, confirmation_token, identities, None)
            .map_err(|_| {
                owner_error(
                    D1TargetWideOwnerAuditClassification::PreparedProductInvalid,
                    "Prepared owner inputs were not the current canonical product",
                )
            })?;
    if prepared.state_bytes() != expected.state_bytes()
        || prepared.receipt().phase != D1DmlAttemptPhase::Prepared
    {
        return Err(owner_error(
            D1TargetWideOwnerAuditClassification::PreparedProductInvalid,
            "Prepared owner product did not match the current canonical product",
        ));
    }
    let claimant_set =
        derive_d1_dml_identity_claimant_set(target, &intended_plan.plan_sha256, identities)
            .map_err(|_| {
                owner_error(
                    D1TargetWideOwnerAuditClassification::PreparedProductInvalid,
                    "Prepared owner identity set was not canonical",
                )
            })?;

    let first = complete_audit(guard)?;
    validate_owner_eligible_audit(&first, guard.dml_custody_authority())?;
    validate_exact_owner(guard, &claimant_set, prepared)?;

    let second = complete_audit(guard)?;
    validate_owner_eligible_audit(&second, guard.dml_custody_authority())?;
    if second != first {
        return Err(owner_error(
            D1TargetWideOwnerAuditClassification::CustodyChanged,
            "complete D1 custody changed during owner authorization",
        ));
    }
    validate_exact_owner(guard, &claimant_set, prepared)?;
    guard.revalidate().map_err(|_| {
        owner_error(
            D1TargetWideOwnerAuditClassification::CustodyChanged,
            "target mutation authority changed during owner authorization",
        )
    })?;

    let receipt = prepared.receipt();
    let surrounding_terminal_attempt_count = second
        .attempt_phase_counts
        .terminal()
        .expect("validated complete audit has exact terminal count");
    let material = OwnerAuthorizationMaterial {
        version: OWNER_AUDIT_VERSION,
        operation: D1_TARGET_WIDE_OWNER_AUDIT_OPERATION,
        consent_version: receipt.consent_version,
        operation_version: receipt.operation_version,
        target_operation: &receipt.target_operation,
        phase: receipt.phase,
        authorization_scope: D1TargetWideOwnerAuthorizationScope::DispatchReservationOnly,
        target_key_sha256: &receipt.target_key_sha256,
        intended_plan_sha256: &receipt.intended_plan_sha256,
        consent_binding_sha256: &receipt.consent_binding_sha256,
        confirmation_token_sha256: &receipt.confirmation_token_sha256,
        operation_id_sha256: &receipt.operation_id_sha256,
        execution_attempt_id_sha256: &receipt.execution_attempt_id_sha256,
        provider_request_id_sha256: &receipt.provider_request_id_sha256,
        attempt_binding_sha256: &receipt.attempt_binding_sha256,
        claimant_set_sha256: claimant_set.claimant_set_sha256(),
        complete_audit_sha256: &second.audit_sha256,
        complete_audit_attempt_count: second.attempt_count,
        surrounding_terminal_attempt_count,
        provider_dispatch_authority: D1DmlCustodyAuditProviderAuthority::None,
        provider_calls: 0,
        provider_mutations: 0,
        local_mutations: 0,
    };
    let authorization_sha256 = hash_serialized(&material);
    Ok(D1TargetWidePreparedOwnerAuthorization {
        version: material.version,
        operation: D1_TARGET_WIDE_OWNER_AUDIT_OPERATION,
        consent_version: material.consent_version,
        operation_version: material.operation_version,
        target_operation: material.target_operation.to_string(),
        phase: material.phase,
        authorization_scope: material.authorization_scope,
        target_key_sha256: material.target_key_sha256.to_string(),
        intended_plan_sha256: material.intended_plan_sha256.to_string(),
        consent_binding_sha256: material.consent_binding_sha256.to_string(),
        confirmation_token_sha256: material.confirmation_token_sha256.to_string(),
        operation_id_sha256: material.operation_id_sha256.to_string(),
        execution_attempt_id_sha256: material.execution_attempt_id_sha256.to_string(),
        provider_request_id_sha256: material.provider_request_id_sha256.to_string(),
        attempt_binding_sha256: material.attempt_binding_sha256.to_string(),
        claimant_set_sha256: material.claimant_set_sha256.to_string(),
        complete_audit_sha256: material.complete_audit_sha256.to_string(),
        complete_audit_attempt_count: material.complete_audit_attempt_count,
        surrounding_terminal_attempt_count,
        provider_dispatch_authority: material.provider_dispatch_authority,
        provider_calls: 0,
        provider_mutations: 0,
        local_mutations: 0,
        authorization_sha256,
    })
}

/// Recompute and exactly compare owner authority immediately before the owned
/// owned local persistence boundary. This function itself never persists.
pub(crate) fn revalidate_d1_target_wide_prepared_owner(
    guard: &D1TargetMutationGuard,
    target: &D1TargetIdentity,
    intended_plan: &D1TargetWideIntendedPlan,
    confirmation_token: &str,
    identities: D1DmlAttemptIdentities<'_>,
    prepared: &D1TargetWidePreparedProduct,
    expected: &D1TargetWidePreparedOwnerAuthorization,
) -> Result<(), CallToolResult> {
    let current = authorize_d1_target_wide_prepared_owner(
        guard,
        target,
        intended_plan,
        confirmation_token,
        identities,
        prepared,
    )?;
    if current != *expected {
        return Err(owner_error(
            D1TargetWideOwnerAuditClassification::AuthorizationChanged,
            "Prepared owner authorization changed before its persistence boundary",
        ));
    }
    guard.revalidate().map_err(|_| {
        owner_error(
            D1TargetWideOwnerAuditClassification::CustodyChanged,
            "target mutation authority changed before its persistence boundary",
        )
    })
}

fn complete_audit(
    guard: &D1TargetMutationGuard,
) -> Result<D1DmlCustodyCompleteAuditReceipt, CallToolResult> {
    guard.audit_d1_dml_custody_complete().map_err(|_| {
        owner_error(
            D1TargetWideOwnerAuditClassification::CompleteAuditUnavailable,
            "complete D1 custody could not be proven from canonical physical artifacts",
        )
    })
}

fn validate_owner_eligible_audit(
    audit: &D1DmlCustodyCompleteAuditReceipt,
    authority: &crate::d1_dml_custody_genesis::D1DmlCustodyAuthority,
) -> Result<(), CallToolResult> {
    let terminal = audit.attempt_phase_counts.terminal();
    let one_owner = audit.attempt_count > 0
        && audit.reconciliation_required
        && audit.attempt_phase_counts.prepared == 1
        && audit.attempt_phase_counts.dispatch_reserved == 0
        && audit.attempt_phase_counts.reconciliation_required == 0
        && terminal == audit.attempt_count.checked_sub(1);
    if audit.validate_complete_graph(authority).is_err() || !one_owner {
        return Err(owner_error(
            D1TargetWideOwnerAuditClassification::CompleteAuditContradictory,
            "complete D1 custody was not exactly one Prepared owner with clean terminal surroundings",
        ));
    }
    Ok(())
}

fn validate_exact_owner(
    guard: &D1TargetMutationGuard,
    claimant_set: &crate::d1_dml_identity_claimant::D1DmlIdentityClaimantSet,
    prepared: &D1TargetWidePreparedProduct,
) -> Result<(), CallToolResult> {
    let binding = &prepared.receipt().attempt_binding_sha256;
    let attempt = guard
        .read_d1_dml_attempt_state(binding)
        .map_err(|_| {
            owner_error(
                D1TargetWideOwnerAuditClassification::OwnerAttemptMissingOrConflicting,
                "Prepared owner attempt could not be read exactly",
            )
        })?
        .ok_or_else(|| {
            owner_error(
                D1TargetWideOwnerAuditClassification::OwnerAttemptMissingOrConflicting,
                "Prepared owner attempt was absent",
            )
        })?;
    if attempt != prepared.state_bytes() {
        return Err(owner_error(
            D1TargetWideOwnerAuditClassification::OwnerAttemptMissingOrConflicting,
            "Prepared owner attempt contradicted the canonical product",
        ));
    }
    for namespace in D1DmlIdentityNamespace::ALL {
        let bytes = guard
            .read_d1_dml_identity_claimant(namespace, claimant_set.identity_sha256(namespace))
            .map_err(|_| {
                owner_error(
                    D1TargetWideOwnerAuditClassification::OwnerClaimantsMissingOrConflicting,
                    "Prepared owner claimant could not be read exactly",
                )
            })?
            .ok_or_else(|| {
                owner_error(
                    D1TargetWideOwnerAuditClassification::OwnerClaimantsMissingOrConflicting,
                    "Prepared owner claimant was absent",
                )
            })?;
        let restored = claimant_set.restore_exact(namespace, &bytes).map_err(|_| {
            owner_error(
                D1TargetWideOwnerAuditClassification::OwnerClaimantsMissingOrConflicting,
                "Prepared owner claimant contradicted the canonical claimant set",
            )
        })?;
        if restored.receipt().phase != D1DmlIdentityClaimantPhase::Bound
            || restored.receipt().attempt_binding_sha256.as_deref() != Some(binding)
        {
            return Err(owner_error(
                D1TargetWideOwnerAuditClassification::OwnerClaimantsMissingOrConflicting,
                "Prepared owner claimant was not exactly Bound to the owner attempt",
            ));
        }
    }
    Ok(())
}

fn owner_error(
    classification: D1TargetWideOwnerAuditClassification,
    message: &'static str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": D1_TARGET_WIDE_OWNER_AUDIT_OPERATION,
        "status": "reconciliation_required",
        "provider_calls": 0,
        "provider_mutations": 0,
        "local_mutations": 0,
        "automatic_retry_permitted": false,
        "provider_dispatch_authority": "none",
        "error": {
            "code": "d1.target_wide_prepared_owner_unproven",
            "classification": classification,
            "message": message,
            "hint": "Retain exact custody; do not reserve or issue a provider operation."
        }
    }))
}

fn hash_serialized<T: Serialize + ?Sized>(value: &T) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(value).expect("owner authorization serialization is infallible")
        )
    )
}

#[cfg(test)]
mod tests;
