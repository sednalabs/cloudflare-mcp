//! Non-causal provider observation for one retained target-wide attempt.
//!
//! This boundary reads the exact target twice and emits aggregate evidence only.
//! It never mutates custody, retries a provider effect, or grants terminal or
//! dispatch authority: a stable current state still cannot identify its actor.

use rmcp::model::CallToolResult;
use serde::{Serialize, Serializer};
use serde_json::json;
use sha2::Digest;

use crate::cloudflare::client::{
    CloudflareClient, D1DatabaseObservationRead, D1DatabaseObservationReadError,
    D1DatabaseObservationState, D1MigrationReconciliationReadLifecycle,
};
use crate::d1_dml_attempt_custody::{D1DmlAttemptIdentities, D1DmlAttemptPhase};
use crate::d1_migration_lease::D1TargetMutationGuard;
use crate::d1_target::D1TargetIdentity;
use crate::d1_target_wide_attempt_custody::{
    D1_TARGET_WIDE_ATTEMPT_CUSTODY_OPERATION, D1TargetWidePreparedProduct,
};
use crate::d1_target_wide_mutation::D1TargetWideIntendedPlan;

const OBSERVATION_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum D1TargetWideObservedState {
    RequestedName,
    DifferentName,
    Exact7404Absent,
    Present,
    Insufficient,
}

impl Serialize for D1TargetWideObservedState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::RequestedName => "requested_name",
            Self::DifferentName => "different_name",
            Self::Exact7404Absent => "exact_7404_absent",
            Self::Present => "present",
            Self::Insufficient => "insufficient",
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWideProviderObservation {
    pub(crate) state: D1TargetWideObservedState,
    pub(crate) response_body_sha256: String,
    pub(crate) response_body_size_bytes: usize,
    pub(crate) http_status: u16,
    pub(crate) lifecycle: D1MigrationReconciliationReadLifecycle,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1TargetWideObservationEvidence {
    pub(crate) version: u8,
    pub(crate) target_key_sha256: String,
    pub(crate) intended_plan_sha256: String,
    pub(crate) consent_binding_sha256: String,
    pub(crate) consent_version: u8,
    pub(crate) operation_version: u8,
    pub(crate) operation_id_sha256: String,
    pub(crate) execution_attempt_id_sha256: String,
    pub(crate) provider_request_id_sha256: String,
    pub(crate) attempt_binding_sha256: String,
    pub(crate) incumbent_provider_evidence_sha256: String,
    pub(crate) before: Option<D1TargetWideProviderObservation>,
    pub(crate) after: Option<D1TargetWideProviderObservation>,
    pub(crate) error_response_body_sha256: Option<String>,
    pub(crate) error_response_body_size_bytes: Option<usize>,
    pub(crate) stable_before_after: bool,
    pub(crate) causality: &'static str,
    pub(crate) terminal_eligibility: &'static str,
    pub(crate) provider_dispatch_authority: &'static str,
    pub(crate) local_mutations: u8,
}

pub(crate) async fn observe_d1_target_wide_attempt(
    client: &CloudflareClient,
    guard: &D1TargetMutationGuard,
    target: &D1TargetIdentity,
    intended_plan: &D1TargetWideIntendedPlan,
    identities: D1DmlAttemptIdentities<'_>,
    incumbent: &D1TargetWidePreparedProduct,
) -> (CallToolResult, D1TargetWideObservationEvidence) {
    let receipt = incumbent.receipt();
    let mut evidence = observation_context(target, intended_plan, identities, receipt);
    if !matches!(
        receipt.phase,
        D1DmlAttemptPhase::DispatchReserved | D1DmlAttemptPhase::ReconciliationRequired
    ) {
        return observation_failure(
            "d1.target_wide_observation_phase_invalid",
            "observation requires one exact retained DispatchReserved or ReconciliationRequired attempt",
            0,
            evidence,
        );
    }
    if !context_matches(target, intended_plan, identities, receipt) {
        return observation_failure(
            "d1.target_wide_observation_context_unproven",
            "observation context did not match the exact retained attempt",
            0,
            evidence,
        );
    }
    if guard.revalidate().is_err() {
        return observation_failure(
            "d1.target_wide_observation_guard_changed",
            "target authority changed before provider observation",
            0,
            evidence,
        );
    }
    let before = match client
        .read_d1_database_for_observation(&target.account_id, &target.database_id)
        .await
    {
        Ok(read) => read,
        Err(error) => return observation_read_failure(error, 0, evidence),
    };
    evidence.before = Some(provider_observation(intended_plan, &before));
    if guard.revalidate().is_err() {
        return observation_failure(
            "d1.target_wide_observation_guard_changed",
            "target authority changed between provider observations",
            1,
            evidence,
        );
    }
    let after = match client
        .read_d1_database_for_observation(&target.account_id, &target.database_id)
        .await
    {
        Ok(read) => read,
        Err(error) => return observation_read_failure(error, 1, evidence),
    };
    evidence.after = Some(provider_observation(intended_plan, &after));
    let stable = evidence.before == evidence.after && guard.revalidate().is_ok();
    evidence.stable_before_after = stable;
    if !stable {
        return observation_failure(
            "d1.target_wide_observation_unstable",
            "provider state or response evidence changed across the bounded observation window",
            2,
            evidence,
        );
    }
    let Some(observation) = evidence.before.as_ref() else {
        unreachable!("stable observation has a before read")
    };
    if observation.state == D1TargetWideObservedState::Insufficient {
        return observation_failure(
            "d1.target_wide_observation_insufficient",
            "the exact provider response was stable but did not establish a requested or different target name",
            2,
            evidence,
        );
    }
    let result = CallToolResult::structured(json!({
        "ok": true,
        "status": "observed_non_causal",
        "observation": evidence,
        "provider_calls": 2,
        "provider_mutations": 0,
        "observed_state": observation.state,
        "automatic_retry_permitted": false,
    }));
    (result, evidence)
}

fn observation_context(
    target: &D1TargetIdentity,
    intended_plan: &D1TargetWideIntendedPlan,
    identities: D1DmlAttemptIdentities<'_>,
    receipt: &crate::d1_target_wide_attempt_custody::D1TargetWidePreparedReceipt,
) -> D1TargetWideObservationEvidence {
    D1TargetWideObservationEvidence {
        version: OBSERVATION_VERSION,
        target_key_sha256: target.target_key_sha256(),
        intended_plan_sha256: intended_plan.plan_sha256.clone(),
        consent_binding_sha256: receipt.consent_binding_sha256.clone(),
        consent_version: receipt.consent_version,
        operation_version: receipt.operation_version,
        operation_id_sha256: hash_bytes(identities.operation_id.as_bytes()),
        execution_attempt_id_sha256: hash_bytes(identities.execution_attempt_id.as_bytes()),
        provider_request_id_sha256: hash_bytes(identities.provider_request_id.as_bytes()),
        attempt_binding_sha256: receipt.attempt_binding_sha256.clone(),
        incumbent_provider_evidence_sha256: incumbent_provider_evidence_sha256(receipt),
        before: None,
        after: None,
        error_response_body_sha256: None,
        error_response_body_size_bytes: None,
        stable_before_after: false,
        causality: "unproven",
        terminal_eligibility: "none",
        provider_dispatch_authority: "none",
        local_mutations: 0,
    }
}

fn context_matches(
    target: &D1TargetIdentity,
    intended_plan: &D1TargetWideIntendedPlan,
    identities: D1DmlAttemptIdentities<'_>,
    receipt: &crate::d1_target_wide_attempt_custody::D1TargetWidePreparedReceipt,
) -> bool {
    receipt.target_key_sha256 == target.target_key_sha256()
        && receipt.operation == D1_TARGET_WIDE_ATTEMPT_CUSTODY_OPERATION
        && receipt.target_operation == intended_plan.consent_binding.operation
        && receipt.custody_generation_sha256 == identities.custody_generation_sha256
        && receipt.intended_plan_sha256 == intended_plan.plan_sha256
        && receipt.operation_id_sha256 == hash_bytes(identities.operation_id.as_bytes())
        && receipt.execution_attempt_id_sha256
            == hash_bytes(identities.execution_attempt_id.as_bytes())
        && receipt.provider_request_id_sha256
            == hash_bytes(identities.provider_request_id.as_bytes())
        && receipt.consent_binding_sha256 == hash_serialized(&intended_plan.consent_binding)
        && receipt.consent_version == intended_plan.consent_binding.consent_version
        && receipt.operation_version == intended_plan.consent_binding.operation_version
}

fn provider_observation(
    intended_plan: &D1TargetWideIntendedPlan,
    read: &D1DatabaseObservationRead,
) -> D1TargetWideProviderObservation {
    D1TargetWideProviderObservation {
        state: classify_state(intended_plan, &read.state),
        response_body_sha256: read.response_body_sha256.clone(),
        response_body_size_bytes: read.response_body_size_bytes,
        http_status: read.lifecycle.http_status.unwrap_or_default(),
        lifecycle: read.lifecycle,
    }
}

fn classify_state(
    intended_plan: &D1TargetWideIntendedPlan,
    state: &D1DatabaseObservationState,
) -> D1TargetWideObservedState {
    match intended_plan.consent_binding.operation {
        "d1_rename_database" => match state {
            D1DatabaseObservationState::Present { name, .. }
                if intended_plan
                    .consent_binding
                    .requested_change
                    .get("new_name")
                    .and_then(|value| value.as_str())
                    == Some(name.as_str()) =>
            {
                D1TargetWideObservedState::RequestedName
            }
            D1DatabaseObservationState::Present { .. } => D1TargetWideObservedState::DifferentName,
            D1DatabaseObservationState::Absent => D1TargetWideObservedState::Insufficient,
        },
        "d1_delete_database" => match state {
            D1DatabaseObservationState::Absent => D1TargetWideObservedState::Exact7404Absent,
            D1DatabaseObservationState::Present { .. } => D1TargetWideObservedState::Present,
        },
        _ => D1TargetWideObservedState::Present,
    }
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

fn observation_read_failure(
    error: D1DatabaseObservationReadError,
    completed_calls: u8,
    evidence: D1TargetWideObservationEvidence,
) -> (CallToolResult, D1TargetWideObservationEvidence) {
    let mut evidence = evidence;
    evidence.error_response_body_sha256 = error.response_body_sha256;
    evidence.error_response_body_size_bytes = error.response_body_size_bytes;
    let provider_calls =
        completed_calls.saturating_add(u8::from(error.lifecycle.dispatch_stage == "attempted"));
    observation_failure(
        error.error.code,
        "provider observation did not produce complete exact evidence",
        provider_calls,
        evidence,
    )
}

fn observation_failure(
    code: &str,
    message: &str,
    provider_calls: u8,
    evidence: D1TargetWideObservationEvidence,
) -> (CallToolResult, D1TargetWideObservationEvidence) {
    let result = CallToolResult::structured_error(json!({
        "ok": false,
        "status": "reconciliation_required",
        "observation": evidence,
        "causality": "unproven",
        "terminal_eligibility": "none",
        "provider_dispatch_authority": "none",
        "local_mutations": 0,
        "provider_calls": provider_calls,
        "provider_mutations": 0,
        "automatic_retry_permitted": false,
        "error": {
            "code": code,
            "message": message,
            "hint": "Retain the exact attempt and treat this as non-causal observation only; never retry or terminalize from it."
        }
    }));
    (result, evidence)
}

fn hash_serialized<T: Serialize + ?Sized>(value: &T) -> String {
    hash_bytes(
        &serde_json::to_vec(value).expect("observation evidence serialization is infallible"),
    )
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(bytes))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::Router;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::get;

    use super::*;
    use crate::config::{ApiTokenSource, CloudflareApiConfig};
    use crate::d1_dml_attempt_custody::{D1DmlAttemptIdentities, TEST_CUSTODY_GENERATION_SHA256};
    use crate::d1_migration_lease::acquire_d1_target_mutation_guard_for_test;
    use crate::d1_target::normalize_d1_target;
    use crate::d1_target_wide_attempt_custody::{
        prepare_d1_target_wide_attempt, prepare_d1_target_wide_dispatch_reservation_cas,
    };
    use crate::d1_target_wide_mutation::rederive_d1_target_wide_intended_plan;

    const DATABASE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    #[derive(Clone, Copy)]
    enum FixtureState {
        Present(&'static str),
        Absent,
        Malformed,
    }

    fn ids() -> D1DmlAttemptIdentities<'static> {
        D1DmlAttemptIdentities {
            operation_id: "observation-operation-0001",
            execution_attempt_id: "observation-attempt-0001",
            provider_request_id: "observation-provider-0001",
            custody_generation_sha256: TEST_CUSTODY_GENERATION_SHA256,
        }
    }

    async fn client_with_states(states: Vec<FixtureState>) -> (CloudflareClient, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/123e4567-e89b-42d3-a456-426614174000",
                get(
                    |State((calls, states)): State<(
                        Arc<AtomicUsize>,
                        Vec<FixtureState>,
                    )>| async move {
                        let ordinal = calls.fetch_add(1, Ordering::SeqCst);
                        match states.get(ordinal).copied().unwrap_or(states[0]) {
                            FixtureState::Present(name) => (
                                StatusCode::OK,
                                axum::Json(json!({
                                    "success": true,
                                    "errors": [],
                                    "messages": [],
                                    "result": {"uuid": DATABASE_ID, "name": name, "version": "production"}
                                })),
                            ),
                            FixtureState::Absent => (
                                StatusCode::NOT_FOUND,
                                axum::Json(json!({
                                    "success": false,
                                    "errors": [{"code": 7404, "message": "database not found"}],
                                    "messages": [],
                                    "result": null
                                })),
                            ),
                            FixtureState::Malformed => (
                                StatusCode::OK,
                                axum::Json(json!({"success": true, "errors": [], "messages": [], "result": {"uuid": DATABASE_ID}})),
                            ),
                        }
                    },
                ),
            )
            .with_state((calls.clone(), states));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind observation fixture");
        let base = format!("http://{}", listener.local_addr().expect("fixture address"));
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve observation fixture");
        });
        let client = fixture_client(base);
        (client, calls)
    }

    fn fixture_client(base: String) -> CloudflareClient {
        CloudflareClient::new(CloudflareApiConfig {
            api_base_url: base,
            api_token: Some("fixture-api-value".to_string()),
            api_token_source: ApiTokenSource::Config,
            api_token_header: "authorization".to_string(),
            r2_access_key_id: None,
            r2_secret_access_key: None,
            r2_endpoint: None,
            default_account_id: Some("acct-1".to_string()),
            default_zone_id: None,
            request_timeout: Duration::from_secs(5),
            max_retries: 0,
            retry_base_delay: Duration::from_millis(1),
            retry_max_delay: Duration::from_millis(1),
            user_agent: "cloudflare-mcp-observation-test".to_string(),
        })
        .expect("observation client")
    }

    fn reserved_attempt(
        guard: &D1TargetMutationGuard,
        target: &D1TargetIdentity,
        plan: &D1TargetWideIntendedPlan,
    ) -> D1TargetWidePreparedProduct {
        guard
            .ensure_target_wide_d1_dml_custody_layout()
            .expect("ensure fixture layout");
        let prepared =
            prepare_d1_target_wide_attempt(target, plan, &plan.confirmation_token(), ids(), None)
                .expect("prepared fixture");
        let reserved = prepare_d1_target_wide_dispatch_reservation_cas(
            target,
            plan,
            &plan.confirmation_token(),
            ids(),
            prepared.state_bytes(),
        )
        .expect("reserved fixture");
        guard
            .create_d1_dml_attempt_state(
                &reserved.receipt().attempt_binding_sha256,
                reserved.state_bytes(),
            )
            .expect("persist reserved fixture");
        reserved
    }

    fn rename_fixture() -> (D1TargetIdentity, D1TargetWideIntendedPlan) {
        let target = normalize_d1_target("acct-1", DATABASE_ID).expect("canonical target");
        let plan = rederive_d1_target_wide_intended_plan(
            &target,
            "d1_rename_database",
            &json!({"new_name": "renamed-db"}),
            Some("synthetic observation reason"),
        )
        .expect("rename plan");
        (target, plan)
    }

    #[tokio::test]
    async fn stable_rename_is_observed_without_causal_authority() {
        let (target, plan) = rename_fixture();
        let (root, guard) =
            acquire_d1_target_mutation_guard_for_test("stable-observation", "d1_rename_database");
        let reserved = reserved_attempt(&guard, &target, &plan);
        let (client, calls) =
            client_with_states(vec![FixtureState::Present("renamed-db"); 2]).await;
        let (result, evidence) =
            observe_d1_target_wide_attempt(&client, &guard, &target, &plan, ids(), &reserved).await;
        let content = result.structured_content.expect("observation result");
        assert_eq!(content["status"], json!("observed_non_causal"));
        assert_eq!(content["observed_state"], json!("requested_name"));
        assert_eq!(content["provider_calls"], json!(2));
        assert_eq!(content["provider_mutations"], json!(0));
        assert_eq!(evidence.causality, "unproven");
        assert_eq!(evidence.terminal_eligibility, "none");
        assert_eq!(evidence.provider_dispatch_authority, "none");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(guard);
        std::fs::remove_dir_all(root).expect("remove observation fixture");
    }

    #[tokio::test]
    async fn unstable_observation_is_nonterminal_and_preserves_attempt() {
        let (target, plan) = rename_fixture();
        let (root, guard) =
            acquire_d1_target_mutation_guard_for_test("unstable-observation", "d1_rename_database");
        let reserved = reserved_attempt(&guard, &target, &plan);
        let incumbent = reserved.state_bytes().to_vec();
        let binding = reserved.receipt().attempt_binding_sha256.clone();
        let (client, calls) = client_with_states(vec![
            FixtureState::Present("renamed-db"),
            FixtureState::Present("other-db"),
        ])
        .await;
        let (result, evidence) =
            observe_d1_target_wide_attempt(&client, &guard, &target, &plan, ids(), &reserved).await;
        let content = result.structured_content.expect("unstable result");
        assert_eq!(content["status"], json!("reconciliation_required"));
        assert_eq!(content["provider_calls"], json!(2));
        assert!(!evidence.stable_before_after);
        assert_eq!(
            guard
                .read_d1_dml_attempt_state(&binding)
                .expect("reserved readback")
                .expect("reserved present"),
            incumbent
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(guard);
        std::fs::remove_dir_all(root).expect("remove observation fixture");
    }

    #[tokio::test]
    async fn stable_delete_7404_is_an_observation_only() {
        let target = normalize_d1_target("acct-1", DATABASE_ID).expect("canonical target");
        let plan = rederive_d1_target_wide_intended_plan(
            &target,
            "d1_delete_database",
            &json!({"delete_database": true}),
            None,
        )
        .expect("delete plan");
        let (root, guard) =
            acquire_d1_target_mutation_guard_for_test("delete-observation", "d1_delete_database");
        let reserved = reserved_attempt(&guard, &target, &plan);
        let (client, calls) = client_with_states(vec![FixtureState::Absent; 2]).await;
        let (result, evidence) =
            observe_d1_target_wide_attempt(&client, &guard, &target, &plan, ids(), &reserved).await;
        assert_eq!(
            result.structured_content.expect("delete result")["observed_state"],
            json!("exact_7404_absent")
        );
        assert!(evidence.stable_before_after);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(guard);
        std::fs::remove_dir_all(root).expect("remove observation fixture");
    }

    #[tokio::test]
    async fn malformed_response_and_wrong_context_fail_closed_without_reads_or_mutation() {
        let (target, plan) = rename_fixture();
        let (root, guard) = acquire_d1_target_mutation_guard_for_test(
            "malformed-observation",
            "d1_rename_database",
        );
        let reserved = reserved_attempt(&guard, &target, &plan);
        let (client, calls) = client_with_states(vec![FixtureState::Malformed]).await;
        let (result, _) =
            observe_d1_target_wide_attempt(&client, &guard, &target, &plan, ids(), &reserved).await;
        assert_eq!(
            result.structured_content.expect("malformed result")["status"],
            json!("reconciliation_required")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let mut wrong_ids = ids();
        wrong_ids.operation_id = "observation-operation-0002";
        let (wrong, _) =
            observe_d1_target_wide_attempt(&client, &guard, &target, &plan, wrong_ids, &reserved)
                .await;
        assert_eq!(
            wrong.structured_content.expect("wrong context result")["provider_calls"],
            json!(0)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(guard);
        std::fs::remove_dir_all(root).expect("remove observation fixture");
    }

    #[tokio::test]
    async fn transport_read_failure_is_noncausal_and_does_not_authorize_retry() {
        let (target, plan) = rename_fixture();
        let (root, guard) = acquire_d1_target_mutation_guard_for_test(
            "transport-observation",
            "d1_rename_database",
        );
        let reserved = reserved_attempt(&guard, &target, &plan);
        let client = fixture_client("http://127.0.0.1:9".to_string());
        let (result, evidence) =
            observe_d1_target_wide_attempt(&client, &guard, &target, &plan, ids(), &reserved).await;
        let content = result.structured_content.expect("transport result");
        assert_eq!(content["status"], json!("reconciliation_required"));
        assert_eq!(content["provider_calls"], json!(1));
        assert_eq!(content["provider_mutations"], json!(0));
        assert_eq!(content["automatic_retry_permitted"], json!(false));
        assert!(!evidence.stable_before_after);
        drop(guard);
        std::fs::remove_dir_all(root).expect("remove observation fixture");
    }

    #[test]
    fn observed_state_serialization_is_aggregate_safe() {
        assert_eq!(
            serde_json::to_value(D1TargetWideObservedState::RequestedName).unwrap(),
            json!("requested_name")
        );
        assert_eq!(
            serde_json::to_value(D1TargetWideObservedState::Exact7404Absent).unwrap(),
            json!("exact_7404_absent")
        );
        assert_eq!(
            serde_json::to_value(D1TargetWideObservedState::Insufficient).unwrap(),
            json!("insufficient")
        );
    }
}
