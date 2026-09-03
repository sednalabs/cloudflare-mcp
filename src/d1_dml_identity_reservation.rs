//! Shared local orchestration for one exact three-namespace D1 identity set.
//!
//! Callers retain their own operation-specific error contract. This module
//! owns only the create-once Pending convergence and Pending-to-Bound CAS seal
//! over the existing strict claimant products and guarded storage primitives.

use rmcp::model::CallToolResult;

use crate::d1_dml_identity_claimant::{
    D1DmlIdentityClaimantPhase, D1DmlIdentityClaimantSet, D1DmlIdentityNamespace,
};
use crate::d1_migration_lease::D1TargetMutationGuard;

pub(crate) fn converge_pending_d1_dml_identity_claimants<F>(
    guard: &D1TargetMutationGuard,
    set: &D1DmlIdentityClaimantSet,
    error_result: F,
) -> Result<(), CallToolResult>
where
    F: Fn(&str, &str, &str) -> CallToolResult,
{
    let mut incumbents = Vec::with_capacity(D1DmlIdentityNamespace::ALL.len());
    for namespace in D1DmlIdentityNamespace::ALL {
        let identity_sha256 = set.identity_sha256(namespace);
        let incumbent = guard
            .read_d1_dml_identity_claimant(namespace, identity_sha256)
            .map_err(|_| {
                error_result(
                    "d1.dml_identity_claimant_custody_unproven",
                    "physical identity claimant presence could not be inspected exactly",
                    "pre_catalog_claimant_inspection",
                )
            })?;
        if let Some(bytes) = incumbent.as_deref() {
            set.restore_exact(namespace, bytes).map_err(|error| {
                error_result(error.code, error.message, "pre_catalog_claimant_conflict")
            })?;
        }
        incumbents.push((namespace, incumbent));
    }

    guard.preflight_d1_dml_identity_claimant_set_capacity(set)?;

    for (namespace, incumbent) in incumbents {
        if incumbent.is_none() {
            let pending = set.pending(namespace);
            guard
                .create_d1_dml_identity_claimant(
                    namespace,
                    set.identity_sha256(namespace),
                    pending.state_bytes(),
                )
                .map_err(|_| {
                    error_result(
                        "d1.dml_identity_claimant_custody_unproven",
                        "one deterministic Pending identity claimant could not be installed exactly",
                        "pre_catalog_claimant_install",
                    )
                })?;
        }
    }

    for namespace in D1DmlIdentityNamespace::ALL {
        let identity_sha256 = set.identity_sha256(namespace);
        let bytes = guard
            .read_d1_dml_identity_claimant(namespace, identity_sha256)
            .map_err(|_| {
                error_result(
                    "d1.dml_identity_claimant_custody_unproven",
                    "identity claimant set could not be reread after installation",
                    "pre_catalog_claimant_readback",
                )
            })?
            .ok_or_else(|| {
                error_result(
                    "d1.dml_identity_claimant_custody_unproven",
                    "one physically required identity claimant was absent after installation",
                    "pre_catalog_claimant_readback",
                )
            })?;
        set.restore_exact(namespace, &bytes).map_err(|error| {
            error_result(error.code, error.message, "pre_catalog_claimant_readback")
        })?;
    }
    Ok(())
}

pub(crate) fn converge_bound_d1_dml_identity_claimants<F>(
    guard: &D1TargetMutationGuard,
    set: &D1DmlIdentityClaimantSet,
    attempt_binding_sha256: &str,
    error_result: F,
) -> Result<(), CallToolResult>
where
    F: Fn(&str, &str, &str) -> CallToolResult,
{
    let mut incumbents = Vec::with_capacity(D1DmlIdentityNamespace::ALL.len());
    for namespace in D1DmlIdentityNamespace::ALL {
        let identity_sha256 = set.identity_sha256(namespace);
        let bytes = guard
            .read_d1_dml_identity_claimant(namespace, identity_sha256)
            .map_err(|_| {
                error_result(
                    "d1.dml_identity_claimant_custody_unproven",
                    "identity claimant could not be inspected before full-binding seal",
                    "post_catalog_claimant_inspection",
                )
            })?
            .ok_or_else(|| {
                error_result(
                    "d1.dml_identity_claimant_custody_unproven",
                    "one physically required identity claimant was absent before seal",
                    "post_catalog_claimant_inspection",
                )
            })?;
        let restored = set.restore_exact(namespace, &bytes).map_err(|error| {
            error_result(error.code, error.message, "post_catalog_claimant_conflict")
        })?;
        if restored.receipt().phase == D1DmlIdentityClaimantPhase::Bound
            && restored.receipt().attempt_binding_sha256.as_deref() != Some(attempt_binding_sha256)
        {
            return Err(error_result(
                "d1.dml_identity_claimant_conflict",
                "identity claimant was already sealed to a conflicting full attempt binding",
                "post_catalog_claimant_conflict",
            ));
        }
        incumbents.push((namespace, restored));
    }

    for (namespace, incumbent) in incumbents {
        if incumbent.receipt().phase == D1DmlIdentityClaimantPhase::Pending {
            let bound = set
                .bound(namespace, attempt_binding_sha256)
                .map_err(|error| {
                    error_result(error.code, error.message, "post_catalog_claimant_seal")
                })?;
            guard
                .compare_exchange_d1_dml_identity_claimant(
                    namespace,
                    set.identity_sha256(namespace),
                    incumbent.state_bytes(),
                    bound.state_bytes(),
                )
                .map_err(|_| {
                    error_result(
                        "d1.dml_identity_claimant_custody_unproven",
                        "Pending identity claimant could not be atomically sealed",
                        "post_catalog_claimant_seal",
                    )
                })?;
        }
    }

    for namespace in D1DmlIdentityNamespace::ALL {
        let identity_sha256 = set.identity_sha256(namespace);
        let bytes = guard
            .read_d1_dml_identity_claimant(namespace, identity_sha256)
            .map_err(|_| {
                error_result(
                    "d1.dml_identity_claimant_custody_unproven",
                    "sealed identity claimant set could not be reread exactly",
                    "post_catalog_claimant_readback",
                )
            })?
            .ok_or_else(|| {
                error_result(
                    "d1.dml_identity_claimant_custody_unproven",
                    "one sealed identity claimant was physically absent",
                    "post_catalog_claimant_readback",
                )
            })?;
        let restored = set.restore_exact(namespace, &bytes).map_err(|error| {
            error_result(error.code, error.message, "post_catalog_claimant_readback")
        })?;
        if restored.receipt().phase != D1DmlIdentityClaimantPhase::Bound
            || restored.receipt().attempt_binding_sha256.as_deref() != Some(attempt_binding_sha256)
        {
            return Err(error_result(
                "d1.dml_identity_claimant_custody_unproven",
                "provider dispatch requires three exact Bound identity claimants",
                "post_catalog_claimant_readback",
            ));
        }
    }
    Ok(())
}
