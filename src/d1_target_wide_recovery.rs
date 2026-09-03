//! Stable provider readback and immutable terminalization for target-wide D1 attempts.
//!
//! Recovery performs authenticated reads only. It never reconstructs or repeats
//! the reserved rename/delete provider mutation.

use mcp_toolkit_core::response_contract::MutationApplyStatus;
use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::cloudflare::client::{
    CloudflareClient, D1DatabaseRecoveryReadError, D1DatabaseRecoveryState,
};
use crate::d1_dml_attempt_custody::{D1DmlAttemptIdentities, D1DmlAttemptPhase};
use crate::d1_migration_lease::D1TargetMutationGuard;
use crate::d1_target::D1TargetIdentity;
use crate::d1_target_wide_attempt_custody::{
    D1TargetWidePreparedProduct, D1TargetWideTerminalEvidence, D1TargetWideTerminalOutcome,
    d1_target_wide_readback_plan_sha256, prepare_d1_target_wide_terminal_cas,
};
use crate::d1_target_wide_mutation::{
    D1TargetWideIntendedPlan, D1TargetWideRecoveryEvidence, D1TargetWideRuntimeState,
};

const TARGET_WIDE_RECOVERY_VERSION: u8 = 1;

#[derive(Serialize)]
struct StableReadbackEvidence<'a> {
    version: u8,
    readback_plan_sha256: &'a str,
    predecessor_state_sha256: &'a str,
    predecessor_phase: D1DmlAttemptPhase,
    incumbent_provider_evidence_sha256: &'a str,
    state_sha256: &'a str,
    before_response_sha256: &'a str,
    before_response_size_bytes: usize,
    before_http_status: u16,
    after_response_sha256: &'a str,
    after_response_size_bytes: usize,
    after_http_status: u16,
    outcome: D1TargetWideTerminalOutcome,
    apply_status: MutationApplyStatus,
}

pub(crate) async fn recover_d1_target_wide_attempt(
    client: &CloudflareClient,
    guard: &D1TargetMutationGuard,
    target: &D1TargetIdentity,
    intended_plan: &D1TargetWideIntendedPlan,
    confirmation_token: &str,
    identities: D1DmlAttemptIdentities<'_>,
    incumbent: D1TargetWidePreparedProduct,
) -> (CallToolResult, D1TargetWideRecoveryEvidence) {
    let receipt = incumbent.receipt();
    if matches!(
        receipt.phase,
        D1DmlAttemptPhase::TerminalApplied | D1DmlAttemptPhase::TerminalNotApplied
    ) {
        let outcome = match receipt.phase {
            D1DmlAttemptPhase::TerminalApplied => D1TargetWideRuntimeState::TerminalApplied,
            D1DmlAttemptPhase::TerminalNotApplied => D1TargetWideRuntimeState::TerminalNotApplied,
            _ => unreachable!(),
        };
        return (
            terminal_result(receipt, 0, true),
            D1TargetWideRecoveryEvidence {
                outcome,
                provider_calls: 0,
                provider_mutations: 0,
                stable_before_after: true,
                terminal_local_mutations: Some(0),
                readback_evidence_sha256: receipt.terminal_evidence_sha256.clone(),
                provider_error_sha256: None,
            },
        );
    }
    if !matches!(
        receipt.phase,
        D1DmlAttemptPhase::DispatchReserved | D1DmlAttemptPhase::ReconciliationRequired
    ) {
        return recovery_failure(
            "d1.target_wide_recovery_phase_invalid",
            "target-wide recovery requires one exact reserved unresolved attempt",
            0,
            None,
        );
    }

    let readback_plan_sha256 = d1_target_wide_readback_plan_sha256(receipt);
    if guard.revalidate().is_err() {
        return recovery_failure(
            "d1.target_wide_recovery_guard_changed",
            "target authority changed before provider readback",
            0,
            None,
        );
    }
    let before = match client
        .read_d1_database_for_recovery(&target.account_id, &target.database_id)
        .await
    {
        Ok(read) => read,
        Err(error) => return recovery_read_failure(error, 0),
    };
    if guard.revalidate().is_err() {
        return recovery_failure(
            "d1.target_wide_recovery_guard_changed",
            "target authority changed between provider readbacks",
            1,
            None,
        );
    }
    let after = match client
        .read_d1_database_for_recovery(&target.account_id, &target.database_id)
        .await
    {
        Ok(read) => read,
        Err(error) => return recovery_read_failure(error, 1),
    };
    if before.state != after.state
        || before.lifecycle.http_status != after.lifecycle.http_status
        || guard.revalidate().is_err()
    {
        return recovery_failure(
            "d1.target_wide_recovery_unstable",
            "provider state or target authority changed across the stable readback window",
            2,
            Some(hash_serialized(&(before.state, after.state))),
        );
    }
    let outcome = match classify_effect(intended_plan, &before.state) {
        Some(outcome) => outcome,
        None => {
            return recovery_failure(
                "d1.target_wide_recovery_insufficient",
                "stable provider state did not prove the intended effect or its absence",
                2,
                Some(hash_serialized(&before.state)),
            );
        }
    };
    if !incumbent_provider_evidence_allows(receipt.apply_status, outcome) {
        return recovery_failure(
            "d1.target_wide_recovery_provider_contradiction",
            "stable provider state contradicted the incumbent provider lifecycle evidence",
            2,
            Some(hash_serialized(&(
                receipt.apply_status,
                receipt.post_provider_outcome,
                &before.state,
            ))),
        );
    }
    let predecessor_state_sha256 = hash_bytes(incumbent.state_bytes());
    let incumbent_provider_evidence_sha256 = hash_serialized(&(
        receipt.post_provider_outcome,
        receipt.apply_status,
        receipt.lifecycle_sha256.as_deref(),
        receipt.http_status,
        receipt.response_body_sha256.as_deref(),
        receipt.response_body_size_bytes,
        receipt.provider_error_sha256.as_deref(),
        receipt.provider_calls,
        receipt.provider_mutations,
    ));
    let state_sha256 = hash_serialized(&before.state);
    let stable_readback_evidence_sha256 = hash_serialized(&StableReadbackEvidence {
        version: TARGET_WIDE_RECOVERY_VERSION,
        readback_plan_sha256: &readback_plan_sha256,
        predecessor_state_sha256: &predecessor_state_sha256,
        predecessor_phase: receipt.phase,
        incumbent_provider_evidence_sha256: &incumbent_provider_evidence_sha256,
        state_sha256: &state_sha256,
        before_response_sha256: &before.response_body_sha256,
        before_response_size_bytes: before.response_body_size_bytes,
        before_http_status: before
            .lifecycle
            .http_status
            .expect("successful recovery read has HTTP status"),
        after_response_sha256: &after.response_body_sha256,
        after_response_size_bytes: after.response_body_size_bytes,
        after_http_status: after
            .lifecycle
            .http_status
            .expect("successful recovery read has HTTP status"),
        outcome,
        apply_status: MutationApplyStatus::Proven,
    });
    let terminal = match prepare_d1_target_wide_terminal_cas(
        target,
        intended_plan,
        confirmation_token,
        identities,
        incumbent.state_bytes(),
        D1TargetWideTerminalEvidence {
            outcome,
            readback_plan_sha256: &readback_plan_sha256,
            stable_readback_evidence_sha256: &stable_readback_evidence_sha256,
            before_response_sha256: &before.response_body_sha256,
            before_response_size_bytes: before.response_body_size_bytes,
            before_http_status: before.lifecycle.http_status.expect("read status"),
            after_response_sha256: &after.response_body_sha256,
            after_response_size_bytes: after.response_body_size_bytes,
            after_http_status: after.lifecycle.http_status.expect("read status"),
        },
    ) {
        Ok(product) => product,
        Err(error) => {
            return recovery_failure(
                error.code,
                error.message,
                2,
                Some(stable_readback_evidence_sha256),
            );
        }
    };
    if guard
        .compare_exchange_d1_dml_attempt_state(
            &receipt.attempt_binding_sha256,
            incumbent.state_bytes(),
            terminal.state_bytes(),
        )
        .is_err()
    {
        return recovery_failure(
            "d1.target_wide_terminal_cas_unproven",
            "terminal state could not be atomically installed from the exact predecessor",
            2,
            Some(stable_readback_evidence_sha256),
        );
    }
    let readback = guard.read_d1_dml_attempt_state(&receipt.attempt_binding_sha256);
    if !matches!(readback, Ok(Some(ref bytes)) if bytes == terminal.state_bytes())
        || guard.revalidate().is_err()
    {
        return recovery_failure(
            "d1.target_wide_terminal_readback_unproven",
            "terminal state did not survive exact guarded readback",
            2,
            Some(stable_readback_evidence_sha256),
        );
    }
    let runtime_outcome = match outcome {
        D1TargetWideTerminalOutcome::Applied => D1TargetWideRuntimeState::TerminalApplied,
        D1TargetWideTerminalOutcome::NotApplied => D1TargetWideRuntimeState::TerminalNotApplied,
    };
    (
        terminal_result(terminal.receipt(), 2, false),
        D1TargetWideRecoveryEvidence {
            outcome: runtime_outcome,
            provider_calls: 2,
            provider_mutations: 0,
            stable_before_after: true,
            terminal_local_mutations: Some(1),
            readback_evidence_sha256: Some(stable_readback_evidence_sha256),
            provider_error_sha256: None,
        },
    )
}

fn classify_effect(
    intended_plan: &D1TargetWideIntendedPlan,
    state: &D1DatabaseRecoveryState,
) -> Option<D1TargetWideTerminalOutcome> {
    match intended_plan.consent_binding.operation {
        "d1_rename_database" => {
            let expected_name = intended_plan
                .consent_binding
                .requested_change
                .get("new_name")?
                .as_str()?;
            match state {
                D1DatabaseRecoveryState::Present { name, .. } if name == expected_name => {
                    Some(D1TargetWideTerminalOutcome::Applied)
                }
                D1DatabaseRecoveryState::Present { .. } => {
                    Some(D1TargetWideTerminalOutcome::NotApplied)
                }
                D1DatabaseRecoveryState::Absent => None,
            }
        }
        "d1_delete_database" => match state {
            D1DatabaseRecoveryState::Absent => Some(D1TargetWideTerminalOutcome::Applied),
            D1DatabaseRecoveryState::Present { .. } => {
                Some(D1TargetWideTerminalOutcome::NotApplied)
            }
        },
        _ => None,
    }
}

fn incumbent_provider_evidence_allows(
    apply_status: Option<MutationApplyStatus>,
    outcome: D1TargetWideTerminalOutcome,
) -> bool {
    match (apply_status, outcome) {
        (Some(MutationApplyStatus::Applied), D1TargetWideTerminalOutcome::Applied)
        | (
            Some(MutationApplyStatus::RejectedBeforeApply),
            D1TargetWideTerminalOutcome::NotApplied,
        )
        | (Some(MutationApplyStatus::UncertainAfterDispatch) | None, _) => true,
        (Some(MutationApplyStatus::Proven), _) => false,
        _ => false,
    }
}

fn terminal_result(
    receipt: &crate::d1_target_wide_attempt_custody::D1TargetWidePreparedReceipt,
    provider_calls: u8,
    exact_replay: bool,
) -> CallToolResult {
    CallToolResult::structured(json!({
        "ok": true,
        "status": match receipt.phase {
            D1DmlAttemptPhase::TerminalApplied => "applied_proven",
            D1DmlAttemptPhase::TerminalNotApplied => "not_applied_proven",
            _ => "reconciliation_required",
        },
        "apply_status": MutationApplyStatus::Proven,
        "provider_calls": provider_calls,
        "provider_mutations": 0,
        "stable_before_after": true,
        "terminal_custody": receipt,
        "exact_replay": exact_replay,
        "automatic_retry_permitted": false,
    }))
}

fn recovery_read_failure(
    error: D1DatabaseRecoveryReadError,
    completed_calls: u8,
) -> (CallToolResult, D1TargetWideRecoveryEvidence) {
    let attempted = u8::from(error.lifecycle.dispatch_stage == "attempted");
    let provider_calls = completed_calls.saturating_add(attempted);
    let digest = hash_serialized(&(
        error.error.code,
        error.error.status,
        error.response_body_sha256.as_deref(),
        error.response_body_size_bytes,
        error.lifecycle,
    ));
    recovery_failure(
        error.error.code,
        "provider readback did not produce exact terminal evidence",
        provider_calls,
        Some(digest),
    )
}

fn recovery_failure(
    code: &str,
    message: &str,
    provider_calls: u8,
    evidence_sha256: Option<String>,
) -> (CallToolResult, D1TargetWideRecoveryEvidence) {
    let provider_error_sha256 = Some(hash_bytes(code.as_bytes()));
    (
        CallToolResult::structured_error(json!({
            "ok": false,
            "status": "reconciliation_required",
            "provider_calls": provider_calls,
            "provider_mutations": 0,
            "stable_before_after": false,
            "automatic_retry_permitted": false,
            "error": {
                "code": code,
                "message": message,
                "hint": "Retain exact custody. Do not repeat or reconstruct the provider mutation."
            }
        })),
        D1TargetWideRecoveryEvidence {
            outcome: D1TargetWideRuntimeState::ReconciliationRequired,
            provider_calls,
            provider_mutations: 0,
            stable_before_after: false,
            terminal_local_mutations: Some(0),
            readback_evidence_sha256: evidence_sha256,
            provider_error_sha256,
        },
    )
}

fn hash_serialized<T: Serialize + ?Sized>(value: &T) -> String {
    hash_bytes(&serde_json::to_vec(value).expect("recovery evidence serialization is infallible"))
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::get;
    use serde_json::json;

    use super::*;
    use crate::config::{ApiTokenSource, CloudflareApiConfig};
    use crate::d1_migration_lease::acquire_d1_target_mutation_guard_for_test;
    use crate::d1_target::normalize_d1_target;
    use crate::d1_target_wide_attempt_custody::{
        prepare_d1_target_wide_attempt, prepare_d1_target_wide_dispatch_reservation_cas,
        restore_bound_d1_target_wide_attempt,
    };
    use crate::d1_target_wide_mutation::rederive_d1_target_wide_intended_plan;

    const DATABASE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn ids() -> D1DmlAttemptIdentities<'static> {
        D1DmlAttemptIdentities {
            operation_id: "recovery-operation-0001",
            execution_attempt_id: "recovery-attempt-0001",
            provider_request_id: "recovery-provider-0001",
        }
    }

    async fn client_with_states(
        states: Vec<Option<&'static str>>,
    ) -> (CloudflareClient, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/123e4567-e89b-42d3-a456-426614174000",
                get(
                    |State((calls, states)): State<(
                        Arc<AtomicUsize>,
                        Vec<Option<&'static str>>,
                    )>,
                     headers: HeaderMap| async move {
                        assert_eq!(
                            headers
                                .get("authorization")
                                .and_then(|value| value.to_str().ok()),
                            Some("Bearer fixture-api-value")
                        );
                        let ordinal = calls.fetch_add(1, Ordering::SeqCst);
                        match states.get(ordinal).copied().flatten().or(states[0]) {
                            Some(name) => (
                                StatusCode::OK,
                                axum::Json(json!({
                                    "success": true,
                                    "errors": [],
                                    "messages": [],
                                    "result": {"uuid": DATABASE_ID, "name": name, "version": "production"}
                                })),
                            ),
                            None => (
                                StatusCode::NOT_FOUND,
                                axum::Json(json!({
                                    "success": false,
                                    "errors": [{"code": 7404, "message": "database not found"}],
                                    "messages": [],
                                    "result": null
                                })),
                            ),
                        }
                    },
                ),
            )
            .with_state((calls.clone(), states));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind recovery fixture");
        let base = format!("http://{}", listener.local_addr().expect("fixture address"));
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve recovery fixture");
        });
        let client = CloudflareClient::new(CloudflareApiConfig {
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
            user_agent: "cloudflare-mcp-recovery-test".to_string(),
        })
        .expect("recovery client");
        (client, calls)
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

    #[tokio::test]
    async fn stable_authenticated_rename_readback_terminalizes_once_and_replay_is_read_only() {
        let target = normalize_d1_target("acct-1", DATABASE_ID).expect("canonical target");
        let plan = rederive_d1_target_wide_intended_plan(
            &target,
            "d1_rename_database",
            &json!({"new_name": "renamed-db"}),
            Some("synthetic reviewed reason"),
        )
        .expect("rename plan");
        let (root, guard) =
            acquire_d1_target_mutation_guard_for_test("stable-recovery", "d1_rename_database");
        let reserved = reserved_attempt(&guard, &target, &plan);
        let binding = reserved.receipt().attempt_binding_sha256.clone();
        let (client, calls) =
            client_with_states(vec![Some("renamed-db"), Some("renamed-db")]).await;
        let (result, evidence) = recover_d1_target_wide_attempt(
            &client,
            &guard,
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            reserved,
        )
        .await;
        let content = result.structured_content.expect("terminal result");
        assert_eq!(content["status"], json!("applied_proven"));
        assert_eq!(content["provider_calls"], json!(2));
        assert_eq!(content["provider_mutations"], json!(0));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(evidence.outcome, D1TargetWideRuntimeState::TerminalApplied);

        let bytes = guard
            .read_d1_dml_attempt_state(&binding)
            .expect("terminal readback")
            .expect("terminal present");
        let terminal = restore_bound_d1_target_wide_attempt(
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            &bytes,
        )
        .expect("restore terminal");
        let mut contradictory: serde_json::Value =
            serde_json::from_slice(&bytes).expect("terminal JSON");
        contradictory["terminal"]["readback_plan_sha256"] = json!("c".repeat(64));
        let mut contradictory_bytes =
            serde_json::to_vec(&contradictory).expect("contradictory terminal JSON");
        contradictory_bytes.push(b'\n');
        assert!(
            restore_bound_d1_target_wide_attempt(
                &target,
                &plan,
                &plan.confirmation_token(),
                ids(),
                &contradictory_bytes,
            )
            .is_err(),
            "canonical-looking terminal evidence must rederive from its predecessor"
        );
        let (replay, replay_evidence) = recover_d1_target_wide_attempt(
            &client,
            &guard,
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            terminal,
        )
        .await;
        let replay = replay.structured_content.expect("terminal replay");
        assert_eq!(replay["status"], json!("applied_proven"));
        assert_eq!(replay["provider_calls"], json!(0));
        assert_eq!(replay["exact_replay"], json!(true));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(replay_evidence.terminal_local_mutations, Some(0));
        drop(guard);
        std::fs::remove_dir_all(root).expect("remove recovery fixture");
    }

    #[tokio::test]
    async fn unstable_readback_retains_reserved_state_without_terminal_mutation() {
        let target = normalize_d1_target("acct-1", DATABASE_ID).expect("canonical target");
        let plan = rederive_d1_target_wide_intended_plan(
            &target,
            "d1_rename_database",
            &json!({"new_name": "renamed-db"}),
            None,
        )
        .expect("rename plan");
        let (root, guard) =
            acquire_d1_target_mutation_guard_for_test("unstable-recovery", "d1_rename_database");
        let reserved = reserved_attempt(&guard, &target, &plan);
        let incumbent = reserved.state_bytes().to_vec();
        let binding = reserved.receipt().attempt_binding_sha256.clone();
        let (client, calls) = client_with_states(vec![Some("renamed-db"), Some("other-db")]).await;
        let (result, evidence) = recover_d1_target_wide_attempt(
            &client,
            &guard,
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            reserved,
        )
        .await;
        let content = result.structured_content.expect("unstable result");
        assert_eq!(content["status"], json!("reconciliation_required"));
        assert_eq!(content["provider_calls"], json!(2));
        assert_eq!(content["provider_mutations"], json!(0));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(evidence.terminal_local_mutations, Some(0));
        assert_eq!(
            guard
                .read_d1_dml_attempt_state(&binding)
                .expect("reserved readback")
                .expect("reserved present"),
            incumbent
        );
        drop(guard);
        std::fs::remove_dir_all(root).expect("remove recovery fixture");
    }

    #[tokio::test]
    async fn stable_authenticated_delete_absence_terminalizes_as_applied() {
        let target = normalize_d1_target("acct-1", DATABASE_ID).expect("canonical target");
        let plan = rederive_d1_target_wide_intended_plan(
            &target,
            "d1_delete_database",
            &json!({"delete_database": true}),
            Some("synthetic reviewed delete"),
        )
        .expect("delete plan");
        let (root, guard) =
            acquire_d1_target_mutation_guard_for_test("delete-recovery", "d1_delete_database");
        let reserved = reserved_attempt(&guard, &target, &plan);
        let (client, calls) = client_with_states(vec![None, None]).await;
        let (result, evidence) = recover_d1_target_wide_attempt(
            &client,
            &guard,
            &target,
            &plan,
            &plan.confirmation_token(),
            ids(),
            reserved,
        )
        .await;
        let content = result.structured_content.expect("delete terminal result");
        assert_eq!(content["status"], json!("applied_proven"));
        assert_eq!(content["provider_calls"], json!(2));
        assert_eq!(content["provider_mutations"], json!(0));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(evidence.outcome, D1TargetWideRuntimeState::TerminalApplied);
        drop(guard);
        std::fs::remove_dir_all(root).expect("remove recovery fixture");
    }

    #[test]
    fn rename_and_delete_effect_matrix_is_closed() {
        let target = normalize_d1_target("acct-1", DATABASE_ID).expect("canonical target");
        let rename = rederive_d1_target_wide_intended_plan(
            &target,
            "d1_rename_database",
            &json!({"new_name": "renamed-db"}),
            None,
        )
        .expect("rename plan");
        let delete = rederive_d1_target_wide_intended_plan(
            &target,
            "d1_delete_database",
            &json!({"delete_database": true}),
            None,
        )
        .expect("delete plan");
        let present = |name: &str| D1DatabaseRecoveryState::Present {
            uuid: DATABASE_ID.to_string(),
            name: name.to_string(),
            version: Some("production".to_string()),
        };
        assert_eq!(
            classify_effect(&rename, &present("renamed-db")),
            Some(D1TargetWideTerminalOutcome::Applied)
        );
        assert_eq!(
            classify_effect(&rename, &present("other-db")),
            Some(D1TargetWideTerminalOutcome::NotApplied)
        );
        assert_eq!(
            classify_effect(&rename, &D1DatabaseRecoveryState::Absent),
            None
        );
        assert_eq!(
            classify_effect(&delete, &D1DatabaseRecoveryState::Absent),
            Some(D1TargetWideTerminalOutcome::Applied)
        );
        assert_eq!(
            classify_effect(&delete, &present("current-db")),
            Some(D1TargetWideTerminalOutcome::NotApplied)
        );
        assert!(incumbent_provider_evidence_allows(
            Some(MutationApplyStatus::Applied),
            D1TargetWideTerminalOutcome::Applied
        ));
        assert!(!incumbent_provider_evidence_allows(
            Some(MutationApplyStatus::Applied),
            D1TargetWideTerminalOutcome::NotApplied
        ));
        assert!(!incumbent_provider_evidence_allows(
            Some(MutationApplyStatus::RejectedBeforeApply),
            D1TargetWideTerminalOutcome::Applied
        ));
        assert!(incumbent_provider_evidence_allows(
            Some(MutationApplyStatus::UncertainAfterDispatch),
            D1TargetWideTerminalOutcome::NotApplied
        ));
    }
}
