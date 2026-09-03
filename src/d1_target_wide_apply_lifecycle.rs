//! Guarded one-call lifecycle for curated target-wide D1 rename/delete.
//!
//! This boundary ends at durable Acknowledged or ReconciliationRequired
//! custody. Stable recovery, provider readback, and terminal finalization are
//! intentionally separate authority.

use rmcp::model::CallToolResult;
use serde_json::json;

use crate::cloudflare::client::CloudflareClient;
use crate::d1_dml_attempt_custody::{D1DmlAttemptIdentities, D1DmlAttemptPhase};
use crate::d1_migration_lease::acquire_d1_target_mutation_guard;
use crate::d1_target::D1TargetIdentity;
use crate::d1_target_wide_attempt_custody::{
    install_d1_target_wide_prepared_custody, prepare_d1_target_wide_attempt,
    prepare_d1_target_wide_dispatch_reservation_cas, record_d1_target_wide_acknowledgement,
    record_d1_target_wide_reconciliation_required, restore_bound_d1_target_wide_attempt,
};
use crate::d1_target_wide_mutation::{
    D1TargetWideExecutionEvidence, D1TargetWideIntendedPlan, rederive_d1_target_wide_intended_plan,
};
use crate::d1_target_wide_owner_audit::{
    authorize_d1_target_wide_prepared_owner, revalidate_d1_target_wide_prepared_owner,
};

enum D1TargetWideDerivedProviderRequest {
    Rename { name: String },
    Delete,
}

pub(crate) struct D1TargetWideApplyInput<'a> {
    pub(crate) intended_plan: &'a D1TargetWideIntendedPlan,
    pub(crate) confirmation_token: &'a str,
    pub(crate) operation_id: &'a str,
    pub(crate) execution_attempt_id: &'a str,
    pub(crate) provider_request_id: &'a str,
}

pub(crate) async fn execute_d1_target_wide_apply(
    client: &CloudflareClient,
    target: &D1TargetIdentity,
    input: D1TargetWideApplyInput<'_>,
) -> (CallToolResult, D1TargetWideExecutionEvidence) {
    let mut evidence = D1TargetWideExecutionEvidence::unobserved(input.intended_plan);
    let provider_request = match derive_provider_request(target, input.intended_plan) {
        Ok(request) => request,
        Err(message) => {
            return (
                blocked("d1.target_wide_provider_request_unproven", message),
                evidence,
            );
        }
    };
    let identities = D1DmlAttemptIdentities {
        operation_id: input.operation_id,
        execution_attempt_id: input.execution_attempt_id,
        provider_request_id: input.provider_request_id,
    };
    let planned = match prepare_d1_target_wide_attempt(
        target,
        input.intended_plan,
        input.confirmation_token,
        identities,
        None,
    ) {
        Ok(product) => product,
        Err(error) => return (blocked(error.code, error.message), evidence),
    };
    let guard = match acquire_d1_target_mutation_guard(
        input.intended_plan.consent_binding.operation,
        &target.account_id,
        &target.database_id,
    ) {
        Ok(guard) => guard,
        Err(result) => return (result, evidence),
    };
    if let Err(result) = observe_layout_ensure(
        &mut evidence,
        guard.ensure_target_wide_d1_dml_custody_layout(),
    ) {
        return (result, evidence);
    }

    let binding = planned.receipt().attempt_binding_sha256.clone();
    let incumbent = match guard.read_d1_dml_attempt_state(&binding) {
        Ok(Some(bytes)) => {
            let restored = match restore_bound_d1_target_wide_attempt(
                target,
                input.intended_plan,
                input.confirmation_token,
                identities,
                &bytes,
            ) {
                Ok(product) => product,
                Err(error) => return (blocked(error.code, error.message), evidence),
            };
            if restored.receipt().phase != D1DmlAttemptPhase::Prepared {
                evidence.provider.provider_calls = 0;
                evidence.provider.provider_mutations = Some(0);
                return (
                    reconciliation_required(
                        "d1.target_wide_attempt_replay",
                        "the exact attempt already has retained nonterminal custody; replay performs no provider mutation or target-state read",
                        Some(restored.receipt()),
                    ),
                    evidence,
                );
            }
            bytes
        }
        Ok(None) => {
            match guard.authorize_target_wide_d1_dml_custody() {
                Ok(authorization) => evidence.audit_authorized(&authorization),
                Err(result) => {
                    evidence.audit_failed();
                    return (result, evidence);
                }
            }
            planned.state_bytes().to_vec()
        }
        Err(result) => return (result, evidence),
    };

    let prepared = match install_d1_target_wide_prepared_custody(
        &guard,
        target,
        input.intended_plan,
        input.confirmation_token,
        identities,
    ) {
        Ok(product) => product,
        Err(result) => return (result, evidence),
    };
    evidence.prepared_installed();
    if prepared.state_bytes() != incumbent {
        return (
            blocked(
                "d1.target_wide_prepared_custody_changed",
                "Prepared custody changed while exact owner authority was being assembled",
            ),
            evidence,
        );
    }
    let owner = match authorize_d1_target_wide_prepared_owner(
        &guard,
        target,
        input.intended_plan,
        input.confirmation_token,
        identities,
        &prepared,
    ) {
        Ok(owner) => owner,
        Err(result) => return (result, evidence),
    };
    if let Err(result) = revalidate_d1_target_wide_prepared_owner(
        &guard,
        target,
        input.intended_plan,
        input.confirmation_token,
        identities,
        &prepared,
        &owner,
    ) {
        evidence.revalidation_failed();
        return (result, evidence);
    }
    evidence.owner_revalidation_matched(&owner.authorization_sha256);
    let reserved = match prepare_d1_target_wide_dispatch_reservation_cas(
        target,
        input.intended_plan,
        input.confirmation_token,
        identities,
        prepared.state_bytes(),
    ) {
        Ok(product) => product,
        Err(error) => return (blocked(error.code, error.message), evidence),
    };
    if guard
        .compare_exchange_d1_dml_attempt_state(
            &binding,
            prepared.state_bytes(),
            reserved.state_bytes(),
        )
        .is_err()
    {
        return (
            blocked(
                "d1.target_wide_dispatch_reservation_unproven",
                "the exact Prepared-to-DispatchReserved compare-and-exchange was not proven",
            ),
            evidence,
        );
    }
    match guard.read_d1_dml_attempt_state(&binding) {
        Ok(Some(bytes)) if bytes == reserved.state_bytes() => {}
        _ => {
            return (
                blocked(
                    "d1.target_wide_dispatch_reservation_unproven",
                    "DispatchReserved custody did not survive exact readback",
                ),
                evidence,
            );
        }
    }
    evidence.dispatch_reserved();
    if guard.revalidate().is_err() {
        return (
            reconciliation_required(
                "d1.target_wide_guard_changed_after_reservation",
                "target authority changed after dispatch reservation; this attempt cannot be retried",
                Some(reserved.receipt()),
            ),
            evidence,
        );
    }

    let provider_result = match provider_request {
        D1TargetWideDerivedProviderRequest::Rename { name } => client
            .rename_d1_database_once_with_lifecycle(
                &target.account_id,
                &target.database_id,
                &name,
                Some(input.provider_request_id),
            )
            .await
            .map(|mutation| {
                (
                    mutation.lifecycle,
                    mutation.response_body_sha256,
                    mutation.response_body_size_bytes,
                )
            }),
        D1TargetWideDerivedProviderRequest::Delete => client
            .delete_d1_database_once_with_lifecycle(
                &target.account_id,
                &target.database_id,
                Some(input.provider_request_id),
            )
            .await
            .map(|mutation| {
                (
                    mutation.lifecycle,
                    mutation.response_body_sha256,
                    mutation.response_body_size_bytes,
                )
            }),
    };
    match provider_result {
        Ok((lifecycle, body_sha256, body_size)) => {
            evidence.provider_succeeded(lifecycle);
            evidence.provider_response_evidence(Some(&body_sha256), Some(body_size), None);
            let acknowledged = match record_d1_target_wide_acknowledgement(
                target,
                input.intended_plan,
                input.confirmation_token,
                identities,
                reserved.state_bytes(),
                lifecycle,
                &body_sha256,
                body_size,
            ) {
                Ok(product) => product,
                Err(error) => {
                    return (
                        post_provider_failure(error.code, error.message, &evidence),
                        evidence,
                    );
                }
            };
            if !persist_post_provider(
                &guard,
                &binding,
                reserved.state_bytes(),
                acknowledged.state_bytes(),
            ) {
                return (
                    post_provider_failure(
                        "d1.target_wide_acknowledgement_custody_unproven",
                        "provider acknowledgement could not be retained and read back exactly",
                        &evidence,
                    ),
                    evidence,
                );
            }
            evidence.post_provider_custody(true);
            (
                CallToolResult::structured(json!({
                    "ok": true,
                    "status": "provider_acknowledged_reconciliation_required",
                    "provider_calls": lifecycle.provider_calls(),
                    "provider_mutations": lifecycle.provider_mutations(),
                    "custody": acknowledged.receipt(),
                    "automatic_retry_permitted": false,
                    "operator_guidance": "Provider acknowledgement is nonterminal. Use the separately reviewed recovery and finalization path."
                })),
                evidence,
            )
        }
        Err(error) => {
            evidence.provider_failed(error.lifecycle);
            evidence.provider_response_evidence(
                error.response_body_sha256.as_deref(),
                error.response_body_size_bytes,
                Some(error.error.code),
            );
            let reconciled = match record_d1_target_wide_reconciliation_required(
                target,
                input.intended_plan,
                input.confirmation_token,
                identities,
                reserved.state_bytes(),
                error.lifecycle,
                error.response_body_sha256.as_deref(),
                error.response_body_size_bytes,
                error.error.code,
            ) {
                Ok(product) => product,
                Err(custody_error) => {
                    return (
                        post_provider_failure(custody_error.code, custody_error.message, &evidence),
                        evidence,
                    );
                }
            };
            if !persist_post_provider(
                &guard,
                &binding,
                reserved.state_bytes(),
                reconciled.state_bytes(),
            ) {
                return (
                    post_provider_failure(
                        "d1.target_wide_reconciliation_custody_unproven",
                        "post-provider reconciliation evidence could not be retained and read back exactly",
                        &evidence,
                    ),
                    evidence,
                );
            }
            evidence.post_provider_custody(false);
            (
                CallToolResult::structured_error(json!({
                    "ok": false,
                    "status": "reconciliation_required",
                    "provider_calls": error.lifecycle.provider_calls(),
                    "provider_mutations": error.lifecycle.provider_mutations(),
                    "custody": reconciled.receipt(),
                    "automatic_retry_permitted": false,
                    "error": {
                        "code": error.error.code,
                        "message": "the reserved provider attempt did not produce terminal authenticated evidence",
                        "hint": "Do not retry this provider-request identity; use the separately reviewed reconciliation path."
                    }
                })),
                evidence,
            )
        }
    }
}

fn derive_provider_request(
    target: &D1TargetIdentity,
    intended_plan: &D1TargetWideIntendedPlan,
) -> Result<D1TargetWideDerivedProviderRequest, &'static str> {
    let canonical = rederive_d1_target_wide_intended_plan(
        target,
        intended_plan.consent_binding.operation,
        &intended_plan.consent_binding.requested_change,
        intended_plan.consent_binding.reason.as_deref(),
    )
    .map_err(|_| "the intended plan could not be re-derived as a closed rename/delete request")?;
    if canonical != *intended_plan {
        return Err("the intended plan did not match its canonical rename/delete request");
    }
    match canonical.consent_binding.operation {
        "d1_rename_database" => canonical
            .consent_binding
            .requested_change
            .as_object()
            .filter(|change| change.len() == 1)
            .and_then(|change| change.get("new_name"))
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty() && name.trim() == *name)
            .map(|name| D1TargetWideDerivedProviderRequest::Rename {
                name: name.to_string(),
            })
            .ok_or("the canonical rename plan did not contain one exact name"),
        "d1_delete_database"
            if canonical.consent_binding.requested_change == json!({"delete_database": true}) =>
        {
            Ok(D1TargetWideDerivedProviderRequest::Delete)
        }
        _ => Err("the canonical intended plan did not select rename or delete"),
    }
}

fn observe_layout_ensure(
    evidence: &mut D1TargetWideExecutionEvidence,
    result: Result<crate::d1_dml_custody_layout::D1DmlCustodyLayoutEnsureOutcome, CallToolResult>,
) -> Result<(), CallToolResult> {
    match result {
        Ok(outcome) => {
            evidence.layout_observed(outcome);
            Ok(())
        }
        Err(result) => {
            evidence.layout_failed();
            Err(result)
        }
    }
}

fn persist_post_provider(
    guard: &crate::d1_migration_lease::D1TargetMutationGuard,
    binding: &str,
    expected: &[u8],
    successor: &[u8],
) -> bool {
    guard
        .compare_exchange_d1_dml_attempt_state(binding, expected, successor)
        .is_ok()
        && matches!(guard.read_d1_dml_attempt_state(binding), Ok(Some(bytes)) if bytes == successor)
}

fn blocked(code: &str, message: &str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "status": "blocked",
        "provider_calls": 0,
        "provider_mutations": 0,
        "automatic_retry_permitted": false,
        "error": {"code": code, "message": message,
            "hint": "Correct the exact guard, consent, identity, version, capacity, audit, or custody condition before a new governed attempt."}
    }))
}

fn reconciliation_required<T: serde::Serialize>(
    code: &str,
    message: &str,
    custody: Option<T>,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "status": "reconciliation_required",
        "provider_calls": 0,
        "provider_mutations": 0,
        "custody": custody,
        "automatic_retry_permitted": false,
        "error": {"code": code, "message": message,
            "hint": "Do not retry this provider-request identity; use the separately reviewed reconciliation path."}
    }))
}

fn post_provider_failure(
    code: &str,
    message: &str,
    evidence: &D1TargetWideExecutionEvidence,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "status": "reconciliation_required",
        "provider_calls": evidence.provider.provider_calls,
        "provider_mutations": evidence.provider.provider_mutations,
        "post_provider_custody": "failed_or_unproven",
        "automatic_retry_permitted": false,
        "error": {"code": code, "message": message,
            "hint": "The provider boundary was reserved or crossed. Never redispatch; reconcile the retained attempt and provider-request identity."}
    }))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::*;
    use crate::config::{ApiTokenSource, CloudflareApiConfig};
    use crate::d1_target::normalize_d1_target;

    fn no_call_client() -> CloudflareClient {
        CloudflareClient::new(CloudflareApiConfig {
            api_base_url: "https://example.invalid".to_string(),
            api_token: Some("fixture-api-value".to_string()),
            api_token_source: ApiTokenSource::Config,
            api_token_header: "authorization".to_string(),
            r2_access_key_id: None,
            r2_secret_access_key: None,
            r2_endpoint: None,
            default_account_id: Some("acct-1".to_string()),
            default_zone_id: None,
            request_timeout: Duration::from_millis(10),
            max_retries: 0,
            retry_base_delay: Duration::from_millis(1),
            retry_max_delay: Duration::from_millis(1),
            user_agent: "cloudflare-mcp-target-wide-test".to_string(),
        })
        .expect("no-call test client")
    }

    #[tokio::test]
    async fn mismatched_provider_effect_is_denied_before_guard_reservation_or_provider() {
        let target = normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000")
            .expect("canonical target");
        let mut intended_plan = rederive_d1_target_wide_intended_plan(
            &target,
            "d1_rename_database",
            &json!({"new_name": "renamed-db"}),
            Some("reviewed synthetic rename"),
        )
        .expect("canonical rename plan");
        match derive_provider_request(&target, &intended_plan)
            .expect("derive provider request from canonical plan")
        {
            D1TargetWideDerivedProviderRequest::Rename { name } => {
                assert_eq!(name, "renamed-db")
            }
            D1TargetWideDerivedProviderRequest::Delete => panic!("rename plan derived delete"),
        }
        let confirmation_token = intended_plan.confirmation_token();
        intended_plan.plan.steps[6].target["body"]["name"] = json!("different-db");

        let (result, evidence) = execute_d1_target_wide_apply(
            &no_call_client(),
            &target,
            D1TargetWideApplyInput {
                intended_plan: &intended_plan,
                confirmation_token: &confirmation_token,
                operation_id: "target-mismatch-operation-0001",
                execution_attempt_id: "target-mismatch-attempt-0001",
                provider_request_id: "target-mismatch-provider-0001",
            },
        )
        .await;
        let content = result
            .structured_content
            .expect("structured mismatch denial");
        assert_eq!(content["status"], json!("blocked"));
        assert_eq!(
            content["error"]["code"],
            json!("d1.target_wide_provider_request_unproven")
        );
        assert_eq!(content["provider_calls"], json!(0));
        assert_eq!(content["provider_mutations"], json!(0));
        assert_eq!(
            serde_json::to_value(&evidence).expect("serialize evidence"),
            json!({
                "intended_plan_sha256": intended_plan.plan_sha256,
                "local_layout": {
                    "outcome": "unobserved",
                    "local_mutations": 0,
                    "provider_dispatch_authority": "none"
                },
                "complete_audit": {"outcome": "runtime_unmaterialized"},
                "final_revalidation": {
                    "outcome": "runtime_unmaterialized",
                    "exact_authorization_identity_matched": Value::Null
                },
                "durable_reservation": {
                    "outcome": "not_installed",
                    "local_mutations": 0,
                    "provider_dispatch_authority": "none"
                },
                "provider": {
                    "outcome": "not_dispatched",
                    "provider_calls": 0,
                    "provider_mutations": 0
                },
                "post_provider_custody": {
                    "outcome": "not_installed",
                    "local_mutations": 0
                }
            })
        );
    }

    #[test]
    fn layout_ensure_failure_records_unknown_local_state_and_zero_provider_calls() {
        let target = normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000")
            .expect("canonical target");
        let intended_plan = rederive_d1_target_wide_intended_plan(
            &target,
            "d1_delete_database",
            &json!({"delete_database": true}),
            Some("reviewed synthetic delete"),
        )
        .expect("canonical delete plan");
        assert!(matches!(
            derive_provider_request(&target, &intended_plan)
                .expect("derive provider request from canonical delete plan"),
            D1TargetWideDerivedProviderRequest::Delete
        ));
        let mut evidence = D1TargetWideExecutionEvidence::unobserved(&intended_plan);
        let result = observe_layout_ensure(
            &mut evidence,
            Err(blocked(
                "d1.target_wide_dml_custody_layout_unavailable",
                "the target-wide layout could not be ensured exactly",
            )),
        );
        assert!(result.is_err());
        assert_eq!(
            serde_json::to_value(&evidence).expect("serialize failed-layout evidence"),
            json!({
                "intended_plan_sha256": intended_plan.plan_sha256,
                "local_layout": {
                    "outcome": "failed",
                    "local_mutations": Value::Null,
                    "provider_dispatch_authority": "none"
                },
                "complete_audit": {"outcome": "runtime_unmaterialized"},
                "final_revalidation": {
                    "outcome": "runtime_unmaterialized",
                    "exact_authorization_identity_matched": Value::Null
                },
                "durable_reservation": {
                    "outcome": "not_installed",
                    "local_mutations": 0,
                    "provider_dispatch_authority": "none"
                },
                "provider": {
                    "outcome": "not_dispatched",
                    "provider_calls": 0,
                    "provider_mutations": 0
                },
                "post_provider_custody": {
                    "outcome": "not_installed",
                    "local_mutations": 0
                }
            })
        );
    }
}
