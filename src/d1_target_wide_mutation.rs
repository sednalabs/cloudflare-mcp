//! Static preview/consent contract for curated target-wide D1 mutations.
//!
//! Rename and delete share this DML-specific plan skeleton. Runtime custody
//! observations are deliberately reported beside the plan, never spliced into
//! it, so dry-run consent and live execution bind identical intended effects.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::cloudflare::d1_database_mutation::D1DatabaseMutationLifecycle;
use crate::d1_dml_custody_layout::{
    D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_SHA256, D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_VERSION,
    D1_DML_CUSTODY_LAYOUT_NAME, D1_DML_CUSTODY_LAYOUT_SHA256, D1_DML_CUSTODY_LAYOUT_VERSION,
    D1DmlCustodyCompleteAuditAuthorization, D1DmlCustodyLayoutEnsureOutcome,
};
use crate::mutation::MutationPlan;
use crate::tools::sha256_bytes_hex;

const TARGET_WIDE_PLAN_VERSION: u8 = 3;
pub(crate) const TARGET_WIDE_OPERATION_VERSION: u8 = 2;
pub(crate) const TARGET_WIDE_CONSENT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct D1TargetWideIntendedPlan {
    pub(crate) plan: MutationPlan,
    pub(crate) plan_sha256: String,
    pub(crate) consent_binding: D1TargetWideConsentBinding,
}

impl D1TargetWideIntendedPlan {
    pub(crate) fn confirmation_token(&self) -> String {
        confirmation_token_for_binding(&self.consent_binding)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct D1TargetWideConsentBinding {
    pub(crate) consent_version: u8,
    pub(crate) operation: &'static str,
    pub(crate) operation_version: u8,
    pub(crate) normalized_target: Value,
    pub(crate) requested_change: Value,
    pub(crate) reason: Option<String>,
    pub(crate) intended_plan_sha256: String,
    pub(crate) plan: MutationPlan,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct D1RenameDatabaseChange {
    new_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct D1DeleteDatabaseChange {
    delete_database: bool,
}

/// Rebuild the only current eight-step target-wide plan from typed canonical
/// request facts. Supplied plan steps, digests, consent versions, and tokens
/// never select or alter the reconstructed product.
pub(crate) fn rederive_d1_target_wide_intended_plan(
    target: &crate::d1_target::D1TargetIdentity,
    operation: &str,
    requested_change: &Value,
    reason: Option<&str>,
) -> Result<D1TargetWideIntendedPlan, &'static str> {
    let normalized = crate::d1_target::normalize_d1_target(&target.account_id, &target.database_id)
        .map_err(|_| "target-wide plan target was not canonical")?;
    if &normalized != target {
        return Err("target-wide plan target was not canonical");
    }
    let normalized_target = json!({
        "account_id": target.account_id,
        "database_id": target.database_id,
    });
    let target_key_sha256 = target.target_key_sha256();
    let provider_path = format!(
        "/accounts/{}/d1/database/{}",
        target.account_id, target.database_id
    );
    match operation {
        "d1_rename_database" => {
            let change = serde_json::from_value::<D1RenameDatabaseChange>(requested_change.clone())
                .map_err(|_| "D1 rename change did not match the closed canonical shape")?;
            if change.new_name.is_empty() || change.new_name.trim() != change.new_name {
                return Err("D1 rename name was not exact canonical input");
            }
            Ok(d1_target_wide_intended_plan(
                "d1_rename_database",
                "validate_d1_database_rename",
                normalized_target,
                json!({"new_name": change.new_name.clone()}),
                reason.map(str::to_string),
                &target_key_sha256,
                "apply_d1_database_patch",
                json!({
                    "method": "PATCH",
                    "path": provider_path,
                    "body": {"name": change.new_name},
                }),
            ))
        }
        "d1_delete_database" => {
            let change = serde_json::from_value::<D1DeleteDatabaseChange>(requested_change.clone())
                .map_err(|_| "D1 delete change did not match the closed canonical shape")?;
            if !change.delete_database {
                return Err("D1 delete change did not request exact deletion");
            }
            Ok(d1_target_wide_intended_plan(
                "d1_delete_database",
                "validate_d1_database_delete",
                normalized_target,
                json!({"delete_database": true}),
                reason.map(str::to_string),
                &target_key_sha256,
                "apply_d1_database_delete",
                json!({
                    "method": "DELETE",
                    "path": provider_path,
                }),
            ))
        }
        _ => Err("target-wide operation was outside rename/delete"),
    }
}

pub(crate) fn d1_target_wide_intended_plan(
    operation: &'static str,
    validation_action: &'static str,
    normalized_target: Value,
    requested_change: Value,
    reason: Option<String>,
    target_key_sha256: &str,
    provider_action: &'static str,
    provider_request: Value,
) -> D1TargetWideIntendedPlan {
    let validation_target = json!({
        "operation_version": TARGET_WIDE_OPERATION_VERSION,
        "normalized_target": normalized_target,
        "requested_change": requested_change,
        "reason": reason,
    });
    let plan = MutationPlan::new(operation)
        .step(validation_action, false, validation_target)
        .step(
            "ensure_d1_dml_custody_layout",
            true,
            json!({
                "target_key_sha256": target_key_sha256,
                "layout": D1_DML_CUSTODY_LAYOUT_NAME,
                "layout_version": D1_DML_CUSTODY_LAYOUT_VERSION,
                "layout_sha256": D1_DML_CUSTODY_LAYOUT_SHA256,
                "conditional": true,
                "execution": "create_if_absent_at_live_guarded_execution",
                "effect_scope": "local_custody_only",
                "provider_dispatch_authority": "none",
            }),
        )
        .step(
            "authorize_complete_d1_dml_custody",
            false,
            json!({
                "target_key_sha256": target_key_sha256,
                "layout_sha256": D1_DML_CUSTODY_LAYOUT_SHA256,
                "audit_budget_version": D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_VERSION,
                "audit_budget_sha256": D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_SHA256,
                "require_clean_complete_audit": true,
                "runtime_identity": "unmaterialized_until_live_guarded_execution",
                "provider_dispatch_authority": "none",
            }),
        )
        .step(
            "install_durable_target_wide_prepared_custody",
            true,
            json!({
                "target_key_sha256": target_key_sha256,
                "required_before_provider_dispatch": true,
                "state": "prepared",
                "effect_scope": "local_durable_attempt_custody",
                "provider_dispatch_authority": "none",
            }),
        )
        .step(
            "authorize_and_revalidate_prepared_owner",
            false,
            json!({
                "target_key_sha256": target_key_sha256,
                "require_exact_owner_and_authorization_identity": true,
                "execution": "immediately_before_dispatch_reservation",
                "provider_dispatch_authority": "none",
            }),
        )
        .step(
            "reserve_one_target_wide_provider_dispatch",
            true,
            json!({
                "target_key_sha256": target_key_sha256,
                "transition": "prepared_to_dispatch_reserved",
                "compare_and_exchange": true,
                "maximum_provider_requests_after_reservation": 1,
            }),
        )
        .step(provider_action, true, provider_request)
        .step(
            "retain_target_wide_post_provider_custody",
            true,
            json!({
                "target_key_sha256": target_key_sha256,
                "outcomes": ["acknowledged", "reconciliation_required"],
                "automatic_retry_permitted": false,
                "stable_recovery_or_finalization": "separate_reviewed_boundary",
            }),
        );
    let plan_sha256 = target_wide_plan_sha256(&plan);
    let consent_binding = D1TargetWideConsentBinding {
        consent_version: TARGET_WIDE_CONSENT_VERSION,
        operation,
        operation_version: TARGET_WIDE_OPERATION_VERSION,
        normalized_target,
        requested_change,
        reason,
        intended_plan_sha256: plan_sha256.clone(),
        plan: plan.clone(),
    };
    D1TargetWideIntendedPlan {
        plan,
        plan_sha256,
        consent_binding,
    }
}

pub(crate) fn target_wide_plan_sha256(plan: &MutationPlan) -> String {
    sha256_bytes_hex(
        &serde_json::to_vec(&json!({
            "version": TARGET_WIDE_PLAN_VERSION,
            "contract": "d1_target_wide_intended_plan",
            "plan": plan,
        }))
        .expect("D1 target-wide intended plan serialization is infallible"),
    )
}

fn confirmation_token_for_binding(binding: &D1TargetWideConsentBinding) -> String {
    let digest = sha256_bytes_hex(
        &serde_json::to_vec(&json!({
            "contract": "d1_target_wide_mutation_consent",
            "binding": binding,
        }))
        .expect("D1 target-wide consent serialization is infallible"),
    );
    format!("cf-d1-target-wide-{}", &digest[..32])
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub(crate) enum D1TargetWideRuntimeState {
    Unobserved,
    RuntimeUnmaterialized,
    Created,
    AlreadyPresent,
    Failed,
    Authorized,
    Matched,
    NotDispatched,
    Succeeded,
    FailedBeforeDispatch,
    UncertainAfterDispatch,
    NotInstalled,
    Prepared,
    DispatchReserved,
    Acknowledged,
    ReconciliationRequired,
    TerminalApplied,
    TerminalNotApplied,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWideLocalLayoutEvidence {
    pub(crate) outcome: D1TargetWideRuntimeState,
    pub(crate) local_mutations: Option<u8>,
    pub(crate) provider_dispatch_authority: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWideAuditEvidence {
    pub(crate) outcome: D1TargetWideRuntimeState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) identity: Option<D1DmlCustodyCompleteAuditAuthorization>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWideRevalidationEvidence {
    pub(crate) outcome: D1TargetWideRuntimeState,
    pub(crate) exact_authorization_identity_matched: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) matched_identity: Option<D1DmlCustodyCompleteAuditAuthorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) owner_authorization_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWideProviderEvidence {
    pub(crate) outcome: D1TargetWideRuntimeState,
    pub(crate) provider_calls: u8,
    pub(crate) provider_mutations: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) lifecycle: Option<D1DatabaseMutationLifecycle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_body_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_body_size_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provider_error_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWideDurableReservationEvidence {
    pub(crate) outcome: D1TargetWideRuntimeState,
    pub(crate) local_mutations: Option<u8>,
    pub(crate) provider_dispatch_authority: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWidePostProviderCustodyEvidence {
    pub(crate) outcome: D1TargetWideRuntimeState,
    pub(crate) local_mutations: Option<u8>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWideExecutionEvidence {
    pub(crate) intended_plan_sha256: String,
    pub(crate) local_layout: D1TargetWideLocalLayoutEvidence,
    pub(crate) complete_audit: D1TargetWideAuditEvidence,
    pub(crate) final_revalidation: D1TargetWideRevalidationEvidence,
    pub(crate) durable_reservation: D1TargetWideDurableReservationEvidence,
    pub(crate) provider: D1TargetWideProviderEvidence,
    pub(crate) post_provider_custody: D1TargetWidePostProviderCustodyEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery: Option<D1TargetWideRecoveryEvidence>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWideRecoveryEvidence {
    pub(crate) outcome: D1TargetWideRuntimeState,
    pub(crate) provider_calls: u8,
    pub(crate) provider_mutations: u8,
    pub(crate) stable_before_after: bool,
    pub(crate) terminal_local_mutations: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) readback_evidence_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provider_error_sha256: Option<String>,
}

// The state transitions remain the exact successor seam for durable provider-
// attempt reservation. Curated live dispatch is gated before these transitions
// until that separately reviewed custody implementation is installed.
#[allow(dead_code)]
impl D1TargetWideExecutionEvidence {
    pub(crate) fn unobserved(plan: &D1TargetWideIntendedPlan) -> Self {
        Self {
            intended_plan_sha256: plan.plan_sha256.clone(),
            local_layout: D1TargetWideLocalLayoutEvidence {
                outcome: D1TargetWideRuntimeState::Unobserved,
                local_mutations: Some(0),
                provider_dispatch_authority: "none",
            },
            complete_audit: D1TargetWideAuditEvidence {
                outcome: D1TargetWideRuntimeState::RuntimeUnmaterialized,
                identity: None,
            },
            final_revalidation: D1TargetWideRevalidationEvidence {
                outcome: D1TargetWideRuntimeState::RuntimeUnmaterialized,
                exact_authorization_identity_matched: None,
                matched_identity: None,
                owner_authorization_sha256: None,
            },
            durable_reservation: D1TargetWideDurableReservationEvidence {
                outcome: D1TargetWideRuntimeState::NotInstalled,
                local_mutations: Some(0),
                provider_dispatch_authority: "none",
            },
            provider: D1TargetWideProviderEvidence {
                outcome: D1TargetWideRuntimeState::NotDispatched,
                provider_calls: 0,
                provider_mutations: Some(0),
                lifecycle: None,
                response_body_sha256: None,
                response_body_size_bytes: None,
                provider_error_sha256: None,
            },
            post_provider_custody: D1TargetWidePostProviderCustodyEvidence {
                outcome: D1TargetWideRuntimeState::NotInstalled,
                local_mutations: Some(0),
            },
            recovery: None,
        }
    }

    pub(crate) fn recovery_evidence(&mut self, evidence: D1TargetWideRecoveryEvidence) {
        self.recovery = Some(evidence);
    }

    pub(crate) fn layout_observed(&mut self, outcome: D1DmlCustodyLayoutEnsureOutcome) {
        let (outcome, local_mutations) = match outcome {
            D1DmlCustodyLayoutEnsureOutcome::Created => {
                (D1TargetWideRuntimeState::Created, Some(1))
            }
            D1DmlCustodyLayoutEnsureOutcome::AlreadyPresent => {
                (D1TargetWideRuntimeState::AlreadyPresent, Some(0))
            }
        };
        self.local_layout.outcome = outcome;
        self.local_layout.local_mutations = local_mutations;
    }

    pub(crate) fn layout_failed(&mut self) {
        self.local_layout.outcome = D1TargetWideRuntimeState::Failed;
        self.local_layout.local_mutations = None;
    }

    pub(crate) fn audit_authorized(
        &mut self,
        authorization: &D1DmlCustodyCompleteAuditAuthorization,
    ) {
        self.complete_audit.outcome = D1TargetWideRuntimeState::Authorized;
        self.complete_audit.identity = Some(authorization.clone());
    }

    pub(crate) fn audit_failed(&mut self) {
        self.complete_audit.outcome = D1TargetWideRuntimeState::Failed;
    }

    pub(crate) fn revalidation_matched(
        &mut self,
        authorization: &D1DmlCustodyCompleteAuditAuthorization,
    ) {
        self.final_revalidation.outcome = D1TargetWideRuntimeState::Matched;
        self.final_revalidation.exact_authorization_identity_matched = Some(true);
        self.final_revalidation.matched_identity = Some(authorization.clone());
    }

    pub(crate) fn revalidation_failed(&mut self) {
        self.final_revalidation.outcome = D1TargetWideRuntimeState::Failed;
        self.final_revalidation.exact_authorization_identity_matched = Some(false);
    }

    pub(crate) fn owner_revalidation_matched(&mut self, authorization_sha256: &str) {
        self.final_revalidation.outcome = D1TargetWideRuntimeState::Matched;
        self.final_revalidation.exact_authorization_identity_matched = Some(true);
        self.final_revalidation.owner_authorization_sha256 = Some(authorization_sha256.to_string());
    }

    pub(crate) fn prepared_installed(&mut self) {
        self.durable_reservation.outcome = D1TargetWideRuntimeState::Prepared;
        self.durable_reservation.local_mutations = None;
    }

    pub(crate) fn dispatch_reserved(&mut self) {
        self.durable_reservation.outcome = D1TargetWideRuntimeState::DispatchReserved;
        self.durable_reservation.local_mutations = Some(1);
    }

    pub(crate) fn post_provider_custody(&mut self, acknowledged: bool) {
        self.post_provider_custody.outcome = if acknowledged {
            D1TargetWideRuntimeState::Acknowledged
        } else {
            D1TargetWideRuntimeState::ReconciliationRequired
        };
        self.post_provider_custody.local_mutations = Some(1);
    }

    pub(crate) fn provider_succeeded(&mut self, lifecycle: D1DatabaseMutationLifecycle) {
        self.provider.outcome = D1TargetWideRuntimeState::Succeeded;
        self.provider.provider_calls = lifecycle.provider_calls();
        self.provider.provider_mutations = lifecycle.provider_mutations();
        self.provider.lifecycle = Some(lifecycle);
    }

    pub(crate) fn provider_failed(&mut self, lifecycle: D1DatabaseMutationLifecycle) {
        self.provider.outcome = if lifecycle.failed_before_dispatch() {
            D1TargetWideRuntimeState::FailedBeforeDispatch
        } else {
            D1TargetWideRuntimeState::UncertainAfterDispatch
        };
        self.provider.provider_calls = lifecycle.provider_calls();
        self.provider.provider_mutations = lifecycle.provider_mutations();
        self.provider.lifecycle = Some(lifecycle);
    }

    pub(crate) fn provider_response_evidence(
        &mut self,
        response_body_sha256: Option<&str>,
        response_body_size_bytes: Option<usize>,
        provider_error_code: Option<&str>,
    ) {
        self.provider.response_body_sha256 = response_body_sha256.map(str::to_string);
        self.provider.response_body_size_bytes = response_body_size_bytes;
        self.provider.provider_error_sha256 =
            provider_error_code.map(|value| sha256_bytes_hex(value.as_bytes()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_target_key_sha256() -> String {
        sha256_bytes_hex(b"synthetic D1 target identity")
    }

    fn delete_plan(reason: &str) -> D1TargetWideIntendedPlan {
        let target_key_sha256 = synthetic_target_key_sha256();
        d1_target_wide_intended_plan(
            "d1_delete_database",
            "validate_d1_database_delete",
            json!({
                "account_id": "acct-example",
                "database_id": "123e4567-e89b-42d3-a456-426614174000",
            }),
            json!({"delete_database": true}),
            Some(reason.to_string()),
            &target_key_sha256,
            "apply_d1_database_delete",
            json!({
                "method": "DELETE",
                "path": "/accounts/acct-example/d1/database/123e4567-e89b-42d3-a456-426614174000",
            }),
        )
    }

    #[test]
    fn delete_consent_binds_every_static_plan_layer() {
        let baseline = delete_plan("retire synthetic fixture");
        let baseline_token = baseline.confirmation_token();
        let target_key_sha256 = synthetic_target_key_sha256();
        assert_eq!(
            serde_json::to_value(&baseline.plan).expect("serialize intended plan"),
            json!({
                "operation": "d1_delete_database",
                "steps": [
                    {"ordinal": 1, "action": "validate_d1_database_delete", "side_effect": false, "target": {
                        "operation_version": TARGET_WIDE_OPERATION_VERSION,
                        "normalized_target": {
                            "account_id": "acct-example",
                            "database_id": "123e4567-e89b-42d3-a456-426614174000",
                        },
                        "requested_change": {"delete_database": true},
                        "reason": "retire synthetic fixture",
                    }},
                    {"ordinal": 2, "action": "ensure_d1_dml_custody_layout", "side_effect": true, "target": {
                        "target_key_sha256": target_key_sha256,
                        "layout": D1_DML_CUSTODY_LAYOUT_NAME,
                        "layout_version": D1_DML_CUSTODY_LAYOUT_VERSION,
                        "layout_sha256": D1_DML_CUSTODY_LAYOUT_SHA256,
                        "conditional": true,
                        "execution": "create_if_absent_at_live_guarded_execution",
                        "effect_scope": "local_custody_only",
                        "provider_dispatch_authority": "none",
                    }},
                    {"ordinal": 3, "action": "authorize_complete_d1_dml_custody", "side_effect": false, "target": {
                        "target_key_sha256": target_key_sha256,
                        "layout_sha256": D1_DML_CUSTODY_LAYOUT_SHA256,
                        "audit_budget_version": D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_VERSION,
                        "audit_budget_sha256": D1_DML_CUSTODY_COMPLETE_AUDIT_BUDGET_SHA256,
                        "require_clean_complete_audit": true,
                        "runtime_identity": "unmaterialized_until_live_guarded_execution",
                        "provider_dispatch_authority": "none",
                    }},
                    {"ordinal": 4, "action": "install_durable_target_wide_prepared_custody", "side_effect": true, "target": {
                        "target_key_sha256": target_key_sha256,
                        "required_before_provider_dispatch": true,
                        "state": "prepared",
                        "effect_scope": "local_durable_attempt_custody",
                        "provider_dispatch_authority": "none",
                    }},
                    {"ordinal": 5, "action": "authorize_and_revalidate_prepared_owner", "side_effect": false, "target": {
                        "target_key_sha256": target_key_sha256,
                        "provider_dispatch_authority": "none",
                        "require_exact_owner_and_authorization_identity": true,
                        "execution": "immediately_before_dispatch_reservation",
                    }},
                    {"ordinal": 6, "action": "reserve_one_target_wide_provider_dispatch", "side_effect": true, "target": {
                        "target_key_sha256": target_key_sha256,
                        "transition": "prepared_to_dispatch_reserved",
                        "compare_and_exchange": true,
                        "maximum_provider_requests_after_reservation": 1,
                    }},
                    {"ordinal": 7, "action": "apply_d1_database_delete", "side_effect": true, "target": {
                        "method": "DELETE",
                        "path": "/accounts/acct-example/d1/database/123e4567-e89b-42d3-a456-426614174000",
                    }},
                    {"ordinal": 8, "action": "retain_target_wide_post_provider_custody", "side_effect": true, "target": {
                        "target_key_sha256": target_key_sha256,
                        "outcomes": ["acknowledged", "reconciliation_required"],
                        "automatic_retry_permitted": false,
                        "stable_recovery_or_finalization": "separate_reviewed_boundary",
                    }},
                ],
            })
        );
        assert_eq!(
            serde_json::to_value(&baseline.consent_binding).expect("serialize consent binding"),
            json!({
                "consent_version": TARGET_WIDE_CONSENT_VERSION,
                "operation": "d1_delete_database",
                "operation_version": TARGET_WIDE_OPERATION_VERSION,
                "normalized_target": {
                    "account_id": "acct-example",
                    "database_id": "123e4567-e89b-42d3-a456-426614174000",
                },
                "requested_change": {"delete_database": true},
                "reason": "retire synthetic fixture",
                "intended_plan_sha256": baseline.plan_sha256,
                "plan": baseline.plan,
            })
        );

        let mut variants = Vec::new();
        let mut reason = baseline.consent_binding.clone();
        reason.reason = Some("different reviewed reason".to_string());
        variants.push(reason);
        let mut target = baseline.consent_binding.clone();
        target.normalized_target["database_id"] = json!("223e4567-e89b-42d3-a456-426614174000");
        variants.push(target);
        let mut requested_change = baseline.consent_binding.clone();
        requested_change.requested_change["delete_database"] = json!(false);
        variants.push(requested_change);
        let mut provider = baseline.consent_binding.clone();
        provider.plan.steps[5].target["method"] = json!("PATCH");
        variants.push(provider);
        let mut layout = baseline.consent_binding.clone();
        layout.plan.steps[1].target["execution"] = json!("different_local_contract");
        variants.push(layout);
        let mut audit = baseline.consent_binding.clone();
        audit.plan.steps[2].target["require_clean_complete_audit"] = json!(false);
        variants.push(audit);
        let mut revalidation = baseline.consent_binding.clone();
        revalidation.plan.steps[3].target["require_exact_authorization_identity"] = json!(false);
        variants.push(revalidation);
        let mut reservation = baseline.consent_binding.clone();
        reservation.plan.steps[4].target["implementation_status"] = json!("installed");
        variants.push(reservation);
        let mut version = baseline.consent_binding.clone();
        version.operation_version += 1;
        variants.push(version);
        let mut operation = baseline.consent_binding.clone();
        operation.operation = "d1_rename_database";
        variants.push(operation);
        let mut consent_version = baseline.consent_binding.clone();
        consent_version.consent_version += 1;
        variants.push(consent_version);
        let mut plan_digest = baseline.consent_binding.clone();
        plan_digest.intended_plan_sha256 = sha256_bytes_hex(b"different static plan");
        variants.push(plan_digest);

        for variant in variants {
            assert_ne!(confirmation_token_for_binding(&variant), baseline_token);
        }
    }

    #[test]
    fn typed_rederivation_closes_rename_and_delete_request_shapes() {
        let target = crate::d1_target::normalize_d1_target(
            "acct-example",
            "123e4567-e89b-42d3-a456-426614174000",
        )
        .expect("canonical target");
        let rename = rederive_d1_target_wide_intended_plan(
            &target,
            "d1_rename_database",
            &json!({"new_name": "canonical-name"}),
            Some("reviewed reason"),
        )
        .expect("typed canonical rename");
        assert_eq!(rename.plan.steps.len(), 8);
        assert_eq!(
            rename.plan.steps[6].target,
            json!({
                "method": "PATCH",
                "path": "/accounts/acct-example/d1/database/123e4567-e89b-42d3-a456-426614174000",
                "body": {"name": "canonical-name"},
            })
        );
        let delete = rederive_d1_target_wide_intended_plan(
            &target,
            "d1_delete_database",
            &json!({"delete_database": true}),
            None,
        )
        .expect("typed canonical delete");
        assert_eq!(delete.plan.steps.len(), 8);
        assert_eq!(
            delete.plan.steps[6].target,
            json!({
                "method": "DELETE",
                "path": "/accounts/acct-example/d1/database/123e4567-e89b-42d3-a456-426614174000",
            })
        );

        for invalid in [
            json!({"new_name": " canonical-name"}),
            json!({"new_name": ""}),
            json!({"new_name": "canonical-name", "unknown": true}),
            json!({"new_name": 7}),
        ] {
            assert!(
                rederive_d1_target_wide_intended_plan(
                    &target,
                    "d1_rename_database",
                    &invalid,
                    None,
                )
                .is_err()
            );
        }
        for invalid in [
            json!({"delete_database": false}),
            json!({"delete_database": true, "unknown": true}),
            json!({"delete_database": "true"}),
        ] {
            assert!(
                rederive_d1_target_wide_intended_plan(
                    &target,
                    "d1_delete_database",
                    &invalid,
                    None,
                )
                .is_err()
            );
        }
        assert!(
            rederive_d1_target_wide_intended_plan(
                &target,
                "d1_unknown_database_operation",
                &json!({}),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn dry_run_evidence_is_separate_from_the_static_plan() {
        let plan = delete_plan("retire synthetic fixture");
        let dry = D1TargetWideExecutionEvidence::unobserved(&plan);
        assert_eq!(
            dry.local_layout.outcome,
            D1TargetWideRuntimeState::Unobserved
        );
        assert_eq!(dry.local_layout.local_mutations, Some(0));
        assert_eq!(
            dry.complete_audit.outcome,
            D1TargetWideRuntimeState::RuntimeUnmaterialized
        );
        assert_eq!(
            dry.final_revalidation.outcome,
            D1TargetWideRuntimeState::RuntimeUnmaterialized
        );
        assert_eq!(
            dry.durable_reservation.outcome,
            D1TargetWideRuntimeState::NotInstalled
        );
        assert_eq!(dry.durable_reservation.local_mutations, Some(0));
        assert_eq!(dry.durable_reservation.provider_dispatch_authority, "none");
        assert_eq!(dry.provider.provider_calls, 0);
        assert_eq!(dry.provider.provider_mutations, Some(0));
    }

    #[test]
    fn provider_lifecycle_maps_without_error_text_inference() {
        let plan = delete_plan("retire synthetic fixture");
        let mut before_dispatch = D1TargetWideExecutionEvidence::unobserved(&plan);
        before_dispatch.provider_failed(D1DatabaseMutationLifecycle::pre_dispatch());
        assert_eq!(
            before_dispatch.provider.outcome,
            D1TargetWideRuntimeState::FailedBeforeDispatch
        );
        assert_eq!(before_dispatch.provider.provider_calls, 0);
        assert_eq!(before_dispatch.provider.provider_mutations, Some(0));

        let mut after_dispatch = D1TargetWideExecutionEvidence::unobserved(&plan);
        after_dispatch.provider_failed(D1DatabaseMutationLifecycle::body_read_failed(200, true));
        assert_eq!(
            after_dispatch.provider.outcome,
            D1TargetWideRuntimeState::UncertainAfterDispatch
        );
        assert_eq!(after_dispatch.provider.provider_calls, 1);
        assert_eq!(after_dispatch.provider.provider_mutations, None);
        assert_eq!(
            after_dispatch
                .provider
                .lifecycle
                .expect("provider lifecycle")
                .body_stage,
            "partially_read"
        );
    }
}
