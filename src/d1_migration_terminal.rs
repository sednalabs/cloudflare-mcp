//! Approval-bound terminal recovery for retained D1 migration manifests.
//!
//! This boundary never retries or submits provider writes. It re-proves one
//! exact retained manifest with primary-current reads, creates one canonical
//! local receipt without replacement, re-proves the same snapshot, and only
//! then retires the retained lease under the permanent target guard.

use rmcp::model::CallToolResult;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::d1_migration_lease::{
    D1RetainedMigrationLease, D1TerminalCustodyNamespace, D1TerminalReconciliationReceipt,
    D1TerminalReconciliationReceiptEvidence, D1TerminalReconciliationReceiptV1,
    inspect_terminal_d1_migration_lease,
};
use crate::d1_migration_manifest::validate_generic_d1_migration_family;
use crate::d1_migration_reconciliation::{
    D1MigrationReconciliationPlanFamily, D1MigrationStateExpectation,
    canonical_effect_assertion_id, prepare_d1_migration_reconciliation_for_expected_query,
    refresh_d1_migration_reconciliation, replay_reconciliation_plan_sha256,
    validate_replay_manifest_expectations,
};
use crate::d1_migration_terminal_semantics::valid_manifest_outcome_prefixes;
use crate::server::CloudflareMcp;
use crate::tools::{D1MigrationManifestEntry, sha256_bytes_hex};

const OPERATION: &str = "d1_finalize_migration_reconciliation";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalCustodyState {
    NotInspected,
    InspectionFailed,
    ActiveVerified,
    RetiringVerified,
    RetiredVerified,
    Unverified,
}

#[derive(Debug)]
struct TerminalEvidence {
    custody: TerminalCustodyState,
    receipt_persisted: Value,
}

pub(crate) fn contextualize_terminal_semantic_error(result: CallToolResult) -> CallToolResult {
    terminalize_failure(
        result,
        TerminalCustodyState::NotInspected,
        0,
        Vec::new(),
        Vec::new(),
        0,
        false,
    )
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1FinalizeMigrationReconciliationArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub database_id: String,
    pub migration_family: String,
    #[serde(default)]
    pub migrations_table: Option<String>,
    pub manifest: Vec<D1MigrationManifestEntry>,
    pub approved_plan_sha256: String,
    pub lease_nonce: String,
    pub lease_payload_sha256: String,
    #[serde(default)]
    pub effect_assertion_id: Option<String>,
    pub state_expectations: Vec<D1MigrationStateExpectation>,
    pub expected_reconciliation_plan_sha256: String,
    pub expected_expectation_proof_sha256: String,
    pub expected_query_sha256: String,
    pub expected_canonical_snapshot_sha256: String,
    pub expected_outcome: String,
    pub expected_original_prefix_length: usize,
    pub expected_current_prefix_length: usize,
    pub terminal_request_sha256: String,
    pub terminal_attempt_sha256: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub approved_terminal_plan_sha256: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn finalize_d1_migration_reconciliation(
    server: &CloudflareMcp,
    account_id: &str,
    database_id: &str,
    family: &str,
    migrations_table: &str,
    manifest: &[D1MigrationManifestEntry],
    approved_plan_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
    effect_assertion_id: Option<&str>,
    state_expectations: Vec<D1MigrationStateExpectation>,
    expected_reconciliation_plan_sha256: &str,
    expected_expectation_proof_sha256: &str,
    expected_query_sha256: &str,
    expected_canonical_snapshot_sha256: &str,
    expected_outcome: &str,
    expected_original_prefix_length: usize,
    expected_current_prefix_length: usize,
    terminal_request_sha256: &str,
    terminal_attempt_sha256: &str,
    dry_run: bool,
    approved_terminal_plan_sha256: Option<&str>,
) -> CallToolResult {
    if let Err(result) = validate_generic_d1_migration_family(family) {
        return contextualize_terminal_semantic_error(result);
    }
    let selected_effect_assertion_id = match canonical_effect_assertion_id(effect_assertion_id) {
        Ok(id) => id,
        Err(result) => return contextualize_terminal_semantic_error(result),
    };
    let replay_expectation_proof_sha256 = match validate_replay_manifest_expectations(
        selected_effect_assertion_id,
        migrations_table,
        manifest,
        &state_expectations,
    ) {
        Ok(proof_sha256) => proof_sha256,
        Err(result) => return contextualize_terminal_semantic_error(result),
    };
    if let Err(result) = validate_terminal_arguments(
        approved_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
        expected_reconciliation_plan_sha256,
        expected_expectation_proof_sha256,
        expected_query_sha256,
        expected_canonical_snapshot_sha256,
        expected_outcome,
        expected_original_prefix_length,
        expected_current_prefix_length,
        manifest.len(),
        terminal_request_sha256,
        terminal_attempt_sha256,
        dry_run,
        approved_terminal_plan_sha256,
    ) {
        return result;
    }

    let target_key_sha256 = sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes());
    let terminal_plan_sha256 = terminal_plan_sha256(
        &target_key_sha256,
        lease_nonce,
        lease_payload_sha256,
        approved_plan_sha256,
        expected_reconciliation_plan_sha256,
        expected_expectation_proof_sha256,
        expected_query_sha256,
        expected_canonical_snapshot_sha256,
        expected_outcome,
        expected_original_prefix_length,
        expected_current_prefix_length,
        terminal_request_sha256,
        terminal_attempt_sha256,
        selected_effect_assertion_id,
    );
    let legacy_terminal_plan_sha256 = (selected_effect_assertion_id == "schema_create_only_v1")
        .then(|| {
            terminal_plan_sha256_v1(
                &target_key_sha256,
                lease_nonce,
                lease_payload_sha256,
                approved_plan_sha256,
                expected_reconciliation_plan_sha256,
                expected_expectation_proof_sha256,
                expected_query_sha256,
                expected_canonical_snapshot_sha256,
                expected_outcome,
                expected_original_prefix_length,
                expected_current_prefix_length,
                terminal_request_sha256,
                terminal_attempt_sha256,
            )
        });
    if !dry_run
        && approved_terminal_plan_sha256 != Some(terminal_plan_sha256.as_str())
        && approved_terminal_plan_sha256 != legacy_terminal_plan_sha256.as_deref()
    {
        return terminal_error(
            "d1.migration_terminal_plan_mismatch",
            "approved_terminal_plan_sha256 does not match the exact pre-existing terminal plan",
            TerminalCustodyState::NotInspected,
            0,
            Vec::new(),
            Vec::new(),
            0,
            false,
        );
    }
    let receipt = D1TerminalReconciliationReceipt {
        version: 2,
        operation: OPERATION.to_string(),
        target_key_sha256: target_key_sha256.clone(),
        lease_nonce: lease_nonce.to_string(),
        lease_payload_sha256: lease_payload_sha256.to_string(),
        approved_apply_plan_sha256: approved_plan_sha256.to_string(),
        effect_assertion_id: selected_effect_assertion_id.to_string(),
        reconciliation_plan_sha256: expected_reconciliation_plan_sha256.to_string(),
        expectation_proof_sha256: expected_expectation_proof_sha256.to_string(),
        query_sha256: expected_query_sha256.to_string(),
        canonical_snapshot_sha256: expected_canonical_snapshot_sha256.to_string(),
        terminal_request_sha256: terminal_request_sha256.to_string(),
        terminal_attempt_sha256: terminal_attempt_sha256.to_string(),
        terminal_plan_sha256: terminal_plan_sha256.clone(),
        outcome: expected_outcome.to_string(),
        original_prefix_length: expected_original_prefix_length,
        current_prefix_length: expected_current_prefix_length,
    };
    let legacy_receipt =
        legacy_terminal_plan_sha256
            .as_ref()
            .map(|legacy_plan| D1TerminalReconciliationReceiptV1 {
                version: 1,
                operation: OPERATION.to_string(),
                target_key_sha256: target_key_sha256.clone(),
                lease_nonce: lease_nonce.to_string(),
                lease_payload_sha256: lease_payload_sha256.to_string(),
                approved_apply_plan_sha256: approved_plan_sha256.to_string(),
                reconciliation_plan_sha256: expected_reconciliation_plan_sha256.to_string(),
                expectation_proof_sha256: expected_expectation_proof_sha256.to_string(),
                query_sha256: expected_query_sha256.to_string(),
                canonical_snapshot_sha256: expected_canonical_snapshot_sha256.to_string(),
                terminal_request_sha256: terminal_request_sha256.to_string(),
                terminal_attempt_sha256: terminal_attempt_sha256.to_string(),
                terminal_plan_sha256: legacy_plan.clone(),
                outcome: expected_outcome.to_string(),
                original_prefix_length: expected_original_prefix_length,
                current_prefix_length: expected_current_prefix_length,
            });

    let initial_lease = match inspect_terminal_d1_migration_lease(
        account_id,
        database_id,
        family,
        approved_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
    ) {
        Ok(lease) => lease,
        Err(result) => {
            return terminalize_failure(
                result,
                TerminalCustodyState::InspectionFailed,
                0,
                Vec::new(),
                Vec::new(),
                0,
                Value::Null,
            );
        }
    };
    let initial_receipt =
        match initial_lease.compatible_terminal_receipt_state(&receipt, legacy_receipt.as_ref()) {
            Ok(evidence) => evidence,
            Err(result) => {
                let evidence =
                    observed_terminal_evidence(&initial_lease, &receipt, legacy_receipt.as_ref());
                return terminalize_failure(
                    result,
                    evidence.custody,
                    0,
                    Vec::new(),
                    Vec::new(),
                    0,
                    evidence.receipt_persisted,
                );
            }
        };
    let mut active_lease_identity = initial_lease.identity.clone();
    active_lease_identity.namespace = "active".to_string();
    if initial_receipt.is_none() && initial_lease.identity.namespace != "active" {
        let evidence =
            observed_terminal_evidence(&initial_lease, &receipt, legacy_receipt.as_ref());
        let message = if initial_lease.is_retired() {
            "terminal retirement exists without its exact terminal receipt"
        } else {
            "terminal retirement began without its exact durable terminal receipt"
        };
        return terminal_error(
            "d1.migration_terminal_receipt_absent",
            message,
            evidence.custody,
            0,
            Vec::new(),
            Vec::new(),
            0,
            evidence.receipt_persisted,
        );
    }
    let recomputed_scoped_reconciliation_plan_sha256 = replay_reconciliation_plan_sha256(
        account_id,
        database_id,
        family,
        migrations_table,
        manifest,
        &active_lease_identity,
        expected_original_prefix_length,
        expected_current_prefix_length,
        expected_outcome,
        expected_query_sha256,
        expected_canonical_snapshot_sha256,
        selected_effect_assertion_id,
        D1MigrationReconciliationPlanFamily::ScopedV3SelectedPrefix,
    );
    let recomputed_historical_v2_reconciliation_plan_sha256 = replay_reconciliation_plan_sha256(
        account_id,
        database_id,
        family,
        migrations_table,
        manifest,
        &active_lease_identity,
        expected_original_prefix_length,
        expected_current_prefix_length,
        expected_outcome,
        expected_query_sha256,
        expected_canonical_snapshot_sha256,
        selected_effect_assertion_id,
        D1MigrationReconciliationPlanFamily::HistoricalV2FullUnion,
    );
    let recomputed_legacy_reconciliation_plan_sha256 =
        (selected_effect_assertion_id == "schema_create_only_v1").then(|| {
            replay_reconciliation_plan_sha256(
                account_id,
                database_id,
                family,
                migrations_table,
                manifest,
                &active_lease_identity,
                expected_original_prefix_length,
                expected_current_prefix_length,
                expected_outcome,
                expected_query_sha256,
                expected_canonical_snapshot_sha256,
                selected_effect_assertion_id,
                D1MigrationReconciliationPlanFamily::LegacyV1FullUnion,
            )
        });
    let scoped_plan_matches =
        recomputed_scoped_reconciliation_plan_sha256 == expected_reconciliation_plan_sha256;
    let historical_v2_plan_matches =
        recomputed_historical_v2_reconciliation_plan_sha256 == expected_reconciliation_plan_sha256;
    let legacy_v1_plan_matches = recomputed_legacy_reconciliation_plan_sha256
        .as_deref()
        .is_some_and(|plan| plan == expected_reconciliation_plan_sha256);
    let plan_family = match (
        legacy_v1_plan_matches,
        historical_v2_plan_matches,
        scoped_plan_matches,
    ) {
        (true, false, false) => D1MigrationReconciliationPlanFamily::LegacyV1FullUnion,
        (false, true, false) => D1MigrationReconciliationPlanFamily::HistoricalV2FullUnion,
        (false, false, true) => D1MigrationReconciliationPlanFamily::ScopedV3SelectedPrefix,
        _ => {
            let evidence =
                observed_terminal_evidence(&initial_lease, &receipt, legacy_receipt.as_ref());
            return terminal_error(
                "d1.migration_terminal_approved_evidence_mismatch",
                "expected reconciliation plan did not identify exactly one legacy-v1, historical-v2, or scoped-v3 query family",
                evidence.custody,
                0,
                Vec::new(),
                Vec::new(),
                0,
                evidence.receipt_persisted,
            );
        }
    };
    if initial_receipt
        .as_ref()
        .is_some_and(|evidence| evidence.receipt_version == 1)
        && plan_family != D1MigrationReconciliationPlanFamily::LegacyV1FullUnion
    {
        let evidence =
            observed_terminal_evidence(&initial_lease, &receipt, legacy_receipt.as_ref());
        return terminal_error(
            "d1.migration_terminal_approved_evidence_mismatch",
            "a predecessor version-1 receipt requires its predecessor reconciliation-plan chronology",
            evidence.custody,
            0,
            Vec::new(),
            Vec::new(),
            0,
            evidence.receipt_persisted,
        );
    }
    if initial_lease.is_retired() {
        let evidence =
            observed_terminal_evidence(&initial_lease, &receipt, legacy_receipt.as_ref());
        return completed_terminal_replay(
            initial_receipt,
            &replay_expectation_proof_sha256,
            expected_expectation_proof_sha256,
            expected_reconciliation_plan_sha256,
            &recomputed_scoped_reconciliation_plan_sha256,
            &recomputed_historical_v2_reconciliation_plan_sha256,
            recomputed_legacy_reconciliation_plan_sha256.as_deref(),
            plan_family,
            &terminal_plan_sha256,
            legacy_terminal_plan_sha256.as_deref(),
            dry_run,
            approved_terminal_plan_sha256,
            evidence,
        );
    }
    let initial_receipt_evidence = initial_receipt;
    let recomputed_plan = match plan_family {
        D1MigrationReconciliationPlanFamily::LegacyV1FullUnion => {
            recomputed_legacy_reconciliation_plan_sha256
                .as_deref()
                .expect("legacy-v1 family is reachable only for the legacy assertion")
        }
        D1MigrationReconciliationPlanFamily::HistoricalV2FullUnion => {
            recomputed_historical_v2_reconciliation_plan_sha256.as_str()
        }
        D1MigrationReconciliationPlanFamily::ScopedV3SelectedPrefix => {
            recomputed_scoped_reconciliation_plan_sha256.as_str()
        }
    };
    if initial_receipt_evidence.is_some()
        && (replay_expectation_proof_sha256 != expected_expectation_proof_sha256
            || recomputed_plan != expected_reconciliation_plan_sha256)
    {
        let evidence =
            observed_terminal_evidence(&initial_lease, &receipt, legacy_receipt.as_ref());
        return terminal_error(
            "d1.migration_terminal_approved_evidence_mismatch",
            "supplied replay manifest does not reproduce the receipt-bound reconciliation plan",
            evidence.custody,
            0,
            Vec::new(),
            Vec::new(),
            0,
            evidence.receipt_persisted,
        );
    }
    let selected_terminal_plan_sha256 = if initial_receipt_evidence
        .as_ref()
        .is_some_and(|evidence| evidence.receipt_version == 1)
    {
        legacy_terminal_plan_sha256
            .as_deref()
            .expect("v1 receipt is reachable only for the legacy assertion")
    } else {
        terminal_plan_sha256.as_str()
    };
    if !dry_run && approved_terminal_plan_sha256 != Some(selected_terminal_plan_sha256) {
        let evidence =
            observed_terminal_evidence(&initial_lease, &receipt, legacy_receipt.as_ref());
        return terminal_error(
            "d1.migration_terminal_plan_mismatch",
            "approved_terminal_plan_sha256 does not match the exact pre-existing terminal plan",
            evidence.custody,
            0,
            Vec::new(),
            Vec::new(),
            0,
            evidence.receipt_persisted,
        );
    }
    let recovering_exact_receipt = initial_receipt_evidence.is_some();
    drop(initial_lease);

    let mut proof = match prepare_d1_migration_reconciliation_for_expected_query(
        server,
        account_id,
        database_id,
        family,
        migrations_table,
        manifest,
        approved_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
        effect_assertion_id,
        state_expectations,
        expected_query_sha256,
        expected_current_prefix_length,
        plan_family,
    )
    .await
    {
        Ok(proof) => proof,
        Err(result) => {
            if let Some(completed) = replay_after_zero_call_prepare_failure(&result, || {
                let completed_lease = inspect_terminal_d1_migration_lease(
                    account_id,
                    database_id,
                    family,
                    approved_plan_sha256,
                    lease_nonce,
                    lease_payload_sha256,
                )
                .ok()?;
                if !completed_lease.is_retired() {
                    return None;
                }
                let completed_receipt = match completed_lease
                    .compatible_terminal_receipt_state(&receipt, legacy_receipt.as_ref())
                {
                    Ok(evidence) => evidence,
                    Err(receipt_error) => {
                        let evidence = observed_terminal_evidence(
                            &completed_lease,
                            &receipt,
                            legacy_receipt.as_ref(),
                        );
                        return Some(terminalize_failure(
                            receipt_error,
                            evidence.custody,
                            0,
                            Vec::new(),
                            Vec::new(),
                            0,
                            evidence.receipt_persisted,
                        ));
                    }
                };
                Some(completed_terminal_replay(
                    completed_receipt,
                    &replay_expectation_proof_sha256,
                    expected_expectation_proof_sha256,
                    expected_reconciliation_plan_sha256,
                    &recomputed_scoped_reconciliation_plan_sha256,
                    &recomputed_historical_v2_reconciliation_plan_sha256,
                    recomputed_legacy_reconciliation_plan_sha256.as_deref(),
                    plan_family,
                    &terminal_plan_sha256,
                    legacy_terminal_plan_sha256.as_deref(),
                    dry_run,
                    approved_terminal_plan_sha256,
                    observed_terminal_evidence(&completed_lease, &receipt, legacy_receipt.as_ref()),
                ))
            }) {
                return completed;
            }
            let evidence = reconciliation_failure_evidence(
                &result,
                account_id,
                database_id,
                family,
                approved_plan_sha256,
                lease_nonce,
                lease_payload_sha256,
                &receipt,
                legacy_receipt.as_ref(),
            );
            return terminalize_failure(
                result,
                evidence.custody,
                0,
                Vec::new(),
                Vec::new(),
                0,
                evidence.receipt_persisted,
            );
        }
    };
    let base_provider_calls = proof.provider_calls();
    let mut response_evidence = proof.response_evidence();
    let mut lifecycle = proof.provider_read_lifecycle();
    let exact_active_plan_matches = (plan_family.uses_predecessor_query_chronology()
        || recovering_exact_receipt)
        && match plan_family {
            D1MigrationReconciliationPlanFamily::LegacyV1FullUnion => {
                proof.legacy_plan_sha256_for_namespace(
                    account_id,
                    database_id,
                    family,
                    migrations_table,
                    manifest,
                    "active",
                ) == expected_reconciliation_plan_sha256
            }
            D1MigrationReconciliationPlanFamily::HistoricalV2FullUnion => {
                proof.historical_v2_plan_sha256_for_namespace(
                    account_id,
                    database_id,
                    family,
                    migrations_table,
                    manifest,
                    "active",
                ) == expected_reconciliation_plan_sha256
            }
            D1MigrationReconciliationPlanFamily::ScopedV3SelectedPrefix => {
                proof.plan_sha256_for_namespace(
                    account_id,
                    database_id,
                    family,
                    migrations_table,
                    manifest,
                    "active",
                ) == expected_reconciliation_plan_sha256
            }
        };
    if (proof.reconciliation_plan_sha256 != expected_reconciliation_plan_sha256
        && !exact_active_plan_matches)
        || proof.expectation_proof_sha256 != expected_expectation_proof_sha256
        || proof.query_sha256() != expected_query_sha256
        || proof.canonical_snapshot_sha256 != expected_canonical_snapshot_sha256
        || proof.outcome != expected_outcome
        || proof.original_prefix_length != expected_original_prefix_length
        || proof.current_prefix_length != expected_current_prefix_length
    {
        let evidence = observed_terminal_evidence(&proof.lease, &receipt, legacy_receipt.as_ref());
        return terminal_error(
            "d1.migration_terminal_approved_evidence_mismatch",
            "fresh retained-manifest proof does not match every independently approved expectation, query, snapshot, outcome, and prefix",
            evidence.custody,
            base_provider_calls,
            response_evidence,
            lifecycle,
            0,
            evidence.receipt_persisted,
        );
    }

    if dry_run {
        let evidence = observed_terminal_evidence(&proof.lease, &receipt, legacy_receipt.as_ref());
        if evidence.custody == TerminalCustodyState::Unverified {
            return terminal_error(
                "d1.migration_terminal_custody_unverified",
                "retained custody could not be revalidated before returning the terminal plan",
                evidence.custody,
                base_provider_calls,
                response_evidence,
                lifecycle,
                0,
                evidence.receipt_persisted,
            );
        }
        return terminal_result(
            json!({
                "ok": true,
                "operation": OPERATION,
                "dry_run": true,
                "status": "terminal_reconciliation_plan_ready",
                "terminal_plan_sha256": selected_terminal_plan_sha256,
                "terminal_receipt_version": initial_receipt_evidence
                    .as_ref()
                    .map(|evidence| evidence.receipt_version),
                "effect_assertion_id": proof.effect_assertion_id,
                "approved_evidence": {
                    "effect_assertion_id": proof.effect_assertion_id,
                    "reconciliation_plan_sha256": expected_reconciliation_plan_sha256,
                    "expectation_proof_sha256": expected_expectation_proof_sha256,
                    "query_sha256": expected_query_sha256,
                    "canonical_snapshot_sha256": expected_canonical_snapshot_sha256,
                    "terminal_request_sha256": terminal_request_sha256,
                    "terminal_attempt_sha256": terminal_attempt_sha256,
                },
                "provider_calls": base_provider_calls,
                "provider_read_lifecycle": lifecycle,
                "response_evidence": response_evidence,
                "provider_mutations": 0,
                "local_namespace_mutations": 0,
                "next_action": "independently approve this exact terminal_plan_sha256 before a live call",
            }),
            evidence.custody,
        );
    }

    let before_receipt = match refresh_d1_migration_reconciliation(
        server,
        &proof,
        account_id,
        database_id,
        manifest,
    )
    .await
    {
        Ok(refresh) => refresh,
        Err(result) => {
            let evidence =
                observed_terminal_evidence(&proof.lease, &receipt, legacy_receipt.as_ref());
            return terminalize_failure(
                result,
                evidence.custody,
                base_provider_calls,
                response_evidence,
                lifecycle,
                0,
                evidence.receipt_persisted,
            );
        }
    };
    response_evidence.push(before_receipt.response_evidence);
    lifecycle.push(before_receipt.lifecycle);

    let (receipt_evidence, receipt_created) = match initial_receipt_evidence {
        Some(evidence) => (evidence, false),
        None => match proof.lease.persist_terminal_receipt(&receipt) {
            Ok(receipt) => receipt,
            Err(failure) => {
                let evidence =
                    observed_terminal_evidence(&proof.lease, &receipt, legacy_receipt.as_ref());
                return terminalize_failure(
                    failure.result,
                    evidence.custody,
                    // The successful pre-receipt refresh is the one completed
                    // provider call after the prepared proof; receipt storage
                    // itself never calls the provider.
                    base_provider_calls + 1,
                    response_evidence,
                    lifecycle,
                    failure.local_namespace_mutations,
                    evidence.receipt_persisted,
                );
            }
        },
    };
    let local_mutations = usize::from(receipt_created);

    let before_retirement = match refresh_d1_migration_reconciliation(
        server,
        &proof,
        account_id,
        database_id,
        manifest,
    )
    .await
    {
        Ok(refresh) => refresh,
        Err(result) => {
            let evidence =
                observed_terminal_evidence(&proof.lease, &receipt, legacy_receipt.as_ref());
            return terminalize_failure(
                result,
                evidence.custody,
                base_provider_calls + 1,
                response_evidence,
                lifecycle,
                local_mutations,
                evidence.receipt_persisted,
            );
        }
    };
    response_evidence.push(before_retirement.response_evidence);
    lifecycle.push(before_retirement.lifecycle);

    let retirement = match proof.lease.retire_after_terminal_receipt(&receipt_evidence) {
        Ok(retirement) => retirement,
        Err(failure) => {
            let evidence =
                observed_terminal_evidence(&proof.lease, &receipt, legacy_receipt.as_ref());
            return terminalize_failure(
                failure.result,
                evidence.custody,
                base_provider_calls + 2,
                response_evidence,
                lifecycle,
                local_mutations + failure.local_namespace_mutations,
                evidence.receipt_persisted,
            );
        }
    };
    terminal_result(
        json!({
            "ok": true,
            "operation": OPERATION,
            "dry_run": false,
            "status": "terminal_reconciliation_complete",
            "replayed": !receipt_created && retirement.local_namespace_mutations == 0,
            "terminal_plan_sha256": selected_terminal_plan_sha256,
            "terminal_receipt_sha256": receipt_evidence.payload_sha256,
            "terminal_receipt_version": receipt_evidence.receipt_version,
            "effect_assertion_id": proof.effect_assertion_id,
            "approved_evidence": {
                "effect_assertion_id": proof.effect_assertion_id,
                "reconciliation_plan_sha256": expected_reconciliation_plan_sha256,
                "expectation_proof_sha256": expected_expectation_proof_sha256,
                "query_sha256": expected_query_sha256,
                "canonical_snapshot_sha256": expected_canonical_snapshot_sha256,
                "terminal_request_sha256": terminal_request_sha256,
                "terminal_attempt_sha256": terminal_attempt_sha256,
            },
            "provider_calls": base_provider_calls + 2,
            "provider_read_lifecycle": lifecycle,
            "response_evidence": response_evidence,
            "provider_mutations": 0,
            "local_namespace_mutations": local_mutations + retirement.local_namespace_mutations,
        }),
        TerminalCustodyState::RetiredVerified,
    )
}

fn replay_after_zero_call_prepare_failure(
    result: &CallToolResult,
    inspect_exact_completion: impl FnOnce() -> Option<CallToolResult>,
) -> Option<CallToolResult> {
    let provider_calls = result
        .structured_content
        .as_ref()
        .and_then(|content| content.get("provider_calls"))
        .and_then(Value::as_u64);
    (provider_calls == Some(0))
        .then(inspect_exact_completion)
        .flatten()
}

#[allow(clippy::too_many_arguments)]
fn completed_terminal_replay(
    receipt_evidence: Option<D1TerminalReconciliationReceiptEvidence>,
    replay_expectation_proof_sha256: &str,
    expected_expectation_proof_sha256: &str,
    expected_reconciliation_plan_sha256: &str,
    recomputed_scoped_reconciliation_plan_sha256: &str,
    recomputed_historical_v2_reconciliation_plan_sha256: &str,
    recomputed_legacy_reconciliation_plan_sha256: Option<&str>,
    plan_family: D1MigrationReconciliationPlanFamily,
    terminal_plan_sha256: &str,
    legacy_terminal_plan_sha256: Option<&str>,
    dry_run: bool,
    approved_terminal_plan_sha256: Option<&str>,
    evidence: TerminalEvidence,
) -> CallToolResult {
    let receipt_evidence = match receipt_evidence {
        None => {
            return terminal_error(
                "d1.migration_terminal_receipt_absent",
                "terminal retirement exists without its exact terminal receipt",
                evidence.custody,
                0,
                Vec::new(),
                Vec::new(),
                0,
                evidence.receipt_persisted,
            );
        }
        Some(evidence) => evidence,
    };
    let recomputed_plan = match plan_family {
        D1MigrationReconciliationPlanFamily::LegacyV1FullUnion => {
            recomputed_legacy_reconciliation_plan_sha256
                .expect("legacy-v1 family is reachable only for the legacy assertion")
        }
        D1MigrationReconciliationPlanFamily::HistoricalV2FullUnion => {
            recomputed_historical_v2_reconciliation_plan_sha256
        }
        D1MigrationReconciliationPlanFamily::ScopedV3SelectedPrefix => {
            recomputed_scoped_reconciliation_plan_sha256
        }
    };
    if (receipt_evidence.receipt_version == 1
        && plan_family != D1MigrationReconciliationPlanFamily::LegacyV1FullUnion)
        || replay_expectation_proof_sha256 != expected_expectation_proof_sha256
        || recomputed_plan != expected_reconciliation_plan_sha256
    {
        return terminal_error(
            "d1.migration_terminal_approved_evidence_mismatch",
            "supplied replay manifest does not reproduce the receipt-bound reconciliation plan",
            evidence.custody,
            0,
            Vec::new(),
            Vec::new(),
            0,
            evidence.receipt_persisted,
        );
    }
    let selected_terminal_plan_sha256 = if receipt_evidence.receipt_version == 1 {
        legacy_terminal_plan_sha256.expect("v1 receipt is reachable only for the legacy assertion")
    } else {
        terminal_plan_sha256
    };
    if !dry_run && approved_terminal_plan_sha256 != Some(selected_terminal_plan_sha256) {
        return terminal_error(
            "d1.migration_terminal_plan_mismatch",
            "approved_terminal_plan_sha256 does not match the exact pre-existing terminal plan",
            evidence.custody,
            0,
            Vec::new(),
            Vec::new(),
            0,
            evidence.receipt_persisted,
        );
    }
    terminal_result(
        json!({
            "ok": true,
            "operation": OPERATION,
            "dry_run": dry_run,
            "status": "terminal_reconciliation_already_complete",
            "replayed": true,
            "terminal_plan_sha256": selected_terminal_plan_sha256,
            "terminal_receipt_sha256": receipt_evidence.payload_sha256,
            "terminal_receipt_version": receipt_evidence.receipt_version,
            "effect_assertion_id": receipt_evidence.effect_assertion_id,
            "provider_calls": 0,
            "provider_read_lifecycle": [],
            "response_evidence": [],
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
        }),
        evidence.custody,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_terminal_arguments(
    approved_plan_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
    expected_reconciliation_plan_sha256: &str,
    expected_expectation_proof_sha256: &str,
    expected_query_sha256: &str,
    expected_canonical_snapshot_sha256: &str,
    expected_outcome: &str,
    expected_original_prefix_length: usize,
    expected_current_prefix_length: usize,
    manifest_length: usize,
    terminal_request_sha256: &str,
    terminal_attempt_sha256: &str,
    dry_run: bool,
    approved_terminal_plan_sha256: Option<&str>,
) -> Result<(), CallToolResult> {
    let hashes = [
        approved_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
        expected_reconciliation_plan_sha256,
        expected_expectation_proof_sha256,
        expected_query_sha256,
        expected_canonical_snapshot_sha256,
        terminal_request_sha256,
        terminal_attempt_sha256,
    ];
    if hashes.into_iter().any(|value| !valid_lower_sha256(value))
        || terminal_request_sha256 == terminal_attempt_sha256
        || !valid_manifest_outcome_prefixes(
            expected_outcome,
            expected_original_prefix_length,
            expected_current_prefix_length,
            manifest_length,
        )
        || (!dry_run
            && approved_terminal_plan_sha256.is_none_or(|value| !valid_lower_sha256(value)))
    {
        return Err(terminal_error(
            "d1.migration_terminal_request_invalid",
            "terminal reconciliation requires canonical distinct request/attempt digests, exact approved evidence, a valid outcome/prefix relationship, and a live approval pin",
            TerminalCustodyState::NotInspected,
            0,
            Vec::new(),
            Vec::new(),
            0,
            false,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn terminal_plan_sha256(
    target_key_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
    approved_plan_sha256: &str,
    reconciliation_plan_sha256: &str,
    expectation_proof_sha256: &str,
    query_sha256: &str,
    snapshot_sha256: &str,
    outcome: &str,
    original_prefix_length: usize,
    current_prefix_length: usize,
    terminal_request_sha256: &str,
    terminal_attempt_sha256: &str,
    effect_assertion_id: &str,
) -> String {
    let plan = json!({
        "version": 1,
        "operation": OPERATION,
        "target_key_sha256": target_key_sha256,
        "lease_nonce": lease_nonce,
        "lease_payload_sha256": lease_payload_sha256,
        "approved_apply_plan_sha256": approved_plan_sha256,
        "effect_assertion_id": effect_assertion_id,
        "reconciliation_plan_sha256": reconciliation_plan_sha256,
        "expectation_proof_sha256": expectation_proof_sha256,
        "query_sha256": query_sha256,
        "canonical_snapshot_sha256": snapshot_sha256,
        "outcome": outcome,
        "original_prefix_length": original_prefix_length,
        "current_prefix_length": current_prefix_length,
        "terminal_request_sha256": terminal_request_sha256,
        "terminal_attempt_sha256": terminal_attempt_sha256,
        "effect": "create_exact_terminal_receipt_then_guarded_retained_lease_retirement",
        "provider_mutations": 0,
    });
    sha256_bytes_hex(&serde_json::to_vec(&plan).expect("terminal plan serialization is infallible"))
}

#[allow(clippy::too_many_arguments)]
fn terminal_plan_sha256_v1(
    target_key_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
    approved_plan_sha256: &str,
    reconciliation_plan_sha256: &str,
    expectation_proof_sha256: &str,
    query_sha256: &str,
    snapshot_sha256: &str,
    outcome: &str,
    original_prefix_length: usize,
    current_prefix_length: usize,
    terminal_request_sha256: &str,
    terminal_attempt_sha256: &str,
) -> String {
    let plan = json!({
        "version": 1,
        "operation": OPERATION,
        "target_key_sha256": target_key_sha256,
        "lease_nonce": lease_nonce,
        "lease_payload_sha256": lease_payload_sha256,
        "approved_apply_plan_sha256": approved_plan_sha256,
        "reconciliation_plan_sha256": reconciliation_plan_sha256,
        "expectation_proof_sha256": expectation_proof_sha256,
        "query_sha256": query_sha256,
        "canonical_snapshot_sha256": snapshot_sha256,
        "outcome": outcome,
        "original_prefix_length": original_prefix_length,
        "current_prefix_length": current_prefix_length,
        "terminal_request_sha256": terminal_request_sha256,
        "terminal_attempt_sha256": terminal_attempt_sha256,
        "effect": "create_exact_terminal_receipt_then_guarded_retained_lease_retirement",
        "provider_mutations": 0,
    });
    sha256_bytes_hex(
        &serde_json::to_vec(&plan).expect("legacy terminal plan serialization is infallible"),
    )
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn observed_terminal_evidence(
    lease: &D1RetainedMigrationLease,
    receipt: &D1TerminalReconciliationReceipt,
    legacy_receipt: Option<&D1TerminalReconciliationReceiptV1>,
) -> TerminalEvidence {
    let readback = lease.terminal_evidence_readback(receipt, legacy_receipt);
    let custody = match readback.custody {
        D1TerminalCustodyNamespace::Active => TerminalCustodyState::ActiveVerified,
        D1TerminalCustodyNamespace::Retiring => TerminalCustodyState::RetiringVerified,
        D1TerminalCustodyNamespace::Retired => TerminalCustodyState::RetiredVerified,
        D1TerminalCustodyNamespace::Unverified => TerminalCustodyState::Unverified,
    };
    TerminalEvidence {
        custody,
        receipt_persisted: readback.receipt_persisted.map_or(Value::Null, Value::Bool),
    }
}

#[allow(clippy::too_many_arguments)]
fn reconciliation_failure_evidence(
    result: &CallToolResult,
    account_id: &str,
    database_id: &str,
    family: &str,
    approved_plan_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
    receipt: &D1TerminalReconciliationReceipt,
    legacy_receipt: Option<&D1TerminalReconciliationReceiptV1>,
) -> TerminalEvidence {
    match result
        .structured_content
        .as_ref()
        .and_then(|content| content.get("custody_status"))
        .and_then(Value::as_str)
    {
        Some("not_inspected") => TerminalEvidence {
            custody: TerminalCustodyState::NotInspected,
            receipt_persisted: Value::Null,
        },
        Some("inspection_failed") => TerminalEvidence {
            custody: TerminalCustodyState::InspectionFailed,
            receipt_persisted: Value::Null,
        },
        Some("retained_evidence_unverified") => TerminalEvidence {
            custody: TerminalCustodyState::Unverified,
            receipt_persisted: Value::Null,
        },
        Some("retained_evidence_verified") => inspect_terminal_d1_migration_lease(
            account_id,
            database_id,
            family,
            approved_plan_sha256,
            lease_nonce,
            lease_payload_sha256,
        )
        .map_or(
            TerminalEvidence {
                custody: TerminalCustodyState::Unverified,
                receipt_persisted: Value::Null,
            },
            |lease| observed_terminal_evidence(&lease, receipt, legacy_receipt),
        ),
        _ => TerminalEvidence {
            custody: TerminalCustodyState::Unverified,
            receipt_persisted: Value::Null,
        },
    }
}

fn apply_terminal_custody(
    content: &mut serde_json::Map<String, Value>,
    custody: TerminalCustodyState,
) {
    content.remove("lease_decision");
    let (custody_status, lease_retained, lease_decision) = match custody {
        TerminalCustodyState::NotInspected => ("not_inspected", Value::Null, None),
        TerminalCustodyState::InspectionFailed => ("inspection_failed", Value::Null, None),
        TerminalCustodyState::ActiveVerified => {
            ("retained_evidence_verified", json!(true), Some("retain"))
        }
        TerminalCustodyState::RetiringVerified => ("retiring_evidence_verified", Value::Null, None),
        TerminalCustodyState::RetiredVerified => {
            ("retired_evidence_verified", json!(false), Some("retired"))
        }
        TerminalCustodyState::Unverified => ("retained_evidence_unverified", Value::Null, None),
    };
    content.insert("lease_retained".to_string(), lease_retained);
    content.insert("custody_status".to_string(), json!(custody_status));
    if let Some(decision) = lease_decision {
        content.insert("lease_decision".to_string(), json!(decision));
    }
}

fn terminal_result(mut content: Value, custody: TerminalCustodyState) -> CallToolResult {
    if let Value::Object(map) = &mut content {
        apply_terminal_custody(map, custody);
    }
    CallToolResult::structured(content)
}

fn terminalize_failure<L, R>(
    result: CallToolResult,
    mut custody: TerminalCustodyState,
    completed_provider_calls: usize,
    prior_response_evidence: Vec<Value>,
    prior_lifecycle: Vec<Value>,
    local_namespace_mutations: L,
    receipt_persisted: R,
) -> CallToolResult
where
    L: Serialize,
    R: Serialize,
{
    let mut content = result.structured_content.unwrap_or_else(|| {
        json!({"error": {"code": "d1.migration_terminal_failed", "message": "terminal reconciliation failed closed"}})
    });
    if content.get("custody_status") == Some(&json!("retained_evidence_unverified")) {
        custody = TerminalCustodyState::Unverified;
    }
    let current_calls = content
        .get("provider_calls")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    let mut response_evidence = prior_response_evidence;
    if let Some(items) = content.get("response_evidence").and_then(Value::as_array) {
        response_evidence.extend(items.iter().cloned());
    }
    let mut lifecycle = prior_lifecycle;
    if let Some(items) = content
        .get("provider_read_lifecycle")
        .and_then(Value::as_array)
    {
        lifecycle.extend(items.iter().cloned());
    }
    if let Value::Object(map) = &mut content {
        map.insert("ok".to_string(), json!(false));
        map.insert("operation".to_string(), json!(OPERATION));
        map.insert("status".to_string(), json!("reconciliation_required"));
        map.insert(
            "retry_decision".to_string(),
            json!("do_not_retry_same_attempt"),
        );
        apply_terminal_custody(map, custody);
        map.insert("receipt_persisted".to_string(), json!(receipt_persisted));
        map.insert(
            "provider_calls".to_string(),
            json!(completed_provider_calls + current_calls),
        );
        map.insert("provider_read_lifecycle".to_string(), json!(lifecycle));
        map.insert("response_evidence".to_string(), json!(response_evidence));
        map.insert("provider_mutations".to_string(), json!(0));
        map.insert(
            "local_namespace_mutations".to_string(),
            json!(local_namespace_mutations),
        );
    }
    CallToolResult::structured_error(content)
}

#[allow(clippy::too_many_arguments)]
fn terminal_error<L, R>(
    code: &'static str,
    message: &'static str,
    custody: TerminalCustodyState,
    provider_calls: usize,
    response_evidence: Vec<Value>,
    lifecycle: Vec<Value>,
    local_namespace_mutations: L,
    receipt_persisted: R,
) -> CallToolResult
where
    L: Serialize,
    R: Serialize,
{
    let mut content = json!({
        "ok": false,
        "operation": OPERATION,
        "status": "reconciliation_required",
        "retry_decision": "do_not_retry_same_attempt",
        "receipt_persisted": receipt_persisted,
        "provider_calls": provider_calls,
        "provider_read_lifecycle": lifecycle,
        "response_evidence": response_evidence,
        "provider_mutations": 0,
        "local_namespace_mutations": local_namespace_mutations,
        "error": {
            "code": code,
            "message": message,
            "hint": "Retain exact custody evidence. Do not retry the provider write or retire the lease outside this guarded terminal boundary."
        }
    });
    if let Value::Object(map) = &mut content {
        apply_terminal_custody(map, custody);
    }
    CallToolResult::structured_error(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custody_cases() -> [(
        TerminalCustodyState,
        &'static str,
        Value,
        Option<&'static str>,
    ); 6] {
        [
            (
                TerminalCustodyState::NotInspected,
                "not_inspected",
                Value::Null,
                None,
            ),
            (
                TerminalCustodyState::InspectionFailed,
                "inspection_failed",
                Value::Null,
                None,
            ),
            (
                TerminalCustodyState::ActiveVerified,
                "retained_evidence_verified",
                json!(true),
                Some("retain"),
            ),
            (
                TerminalCustodyState::RetiringVerified,
                "retiring_evidence_verified",
                Value::Null,
                None,
            ),
            (
                TerminalCustodyState::RetiredVerified,
                "retired_evidence_verified",
                json!(false),
                Some("retired"),
            ),
            (
                TerminalCustodyState::Unverified,
                "retained_evidence_unverified",
                Value::Null,
                None,
            ),
        ]
    }

    fn add_expected_custody(
        value: &mut Value,
        custody_status: &str,
        lease_retained: Value,
        lease_decision: Option<&str>,
    ) {
        let map = value.as_object_mut().expect("expected object");
        map.insert("custody_status".to_string(), json!(custody_status));
        map.insert("lease_retained".to_string(), lease_retained);
        if let Some(decision) = lease_decision {
            map.insert("lease_decision".to_string(), json!(decision));
        }
    }

    #[test]
    fn direct_terminal_errors_report_only_proven_custody_authority() {
        for (custody, custody_status, lease_retained, lease_decision) in custody_cases() {
            let actual = terminal_error(
                "d1.test_terminal_failure",
                "synthetic terminal failure",
                custody,
                0,
                Vec::new(),
                Vec::new(),
                0,
                false,
            )
            .structured_content
            .expect("structured terminal error");
            let mut expected = json!({
                "ok": false,
                "operation": OPERATION,
                "status": "reconciliation_required",
                "retry_decision": "do_not_retry_same_attempt",
                "receipt_persisted": false,
                "provider_calls": 0,
                "provider_read_lifecycle": [],
                "response_evidence": [],
                "provider_mutations": 0,
                "local_namespace_mutations": 0,
                "error": {
                    "code": "d1.test_terminal_failure",
                    "message": "synthetic terminal failure",
                    "hint": "Retain exact custody evidence. Do not retry the provider write or retire the lease outside this guarded terminal boundary."
                }
            });
            add_expected_custody(
                &mut expected,
                custody_status,
                lease_retained,
                lease_decision,
            );
            assert_eq!(actual, expected, "{custody:?}");
        }
    }

    #[test]
    fn direct_terminalized_failures_do_not_overwrite_custody_authority() {
        for (custody, custody_status, lease_retained, lease_decision) in custody_cases() {
            let upstream = CallToolResult::structured_error(json!({
                "lease_decision": "stale",
                "lease_retained": true,
                "custody_status": "stale",
                "provider_calls": 1,
                "provider_read_lifecycle": [{"dispatch_stage": "attempted"}],
                "response_evidence": [{"response_body_sha256": "a"}],
                "error": {"code": "d1.test_upstream", "message": "upstream failure"}
            }));
            let actual = terminalize_failure(
                upstream,
                custody,
                2,
                vec![json!({"response_body_sha256": "b"})],
                vec![json!({"dispatch_stage": "received"})],
                0,
                false,
            )
            .structured_content
            .expect("structured terminalized error");
            let mut expected = json!({
                "ok": false,
                "operation": OPERATION,
                "status": "reconciliation_required",
                "retry_decision": "do_not_retry_same_attempt",
                "receipt_persisted": false,
                "provider_calls": 3,
                "provider_read_lifecycle": [
                    {"dispatch_stage": "received"},
                    {"dispatch_stage": "attempted"}
                ],
                "response_evidence": [
                    {"response_body_sha256": "b"},
                    {"response_body_sha256": "a"}
                ],
                "provider_mutations": 0,
                "local_namespace_mutations": 0,
                "error": {"code": "d1.test_upstream", "message": "upstream failure"}
            });
            add_expected_custody(
                &mut expected,
                custody_status,
                lease_retained,
                lease_decision,
            );
            assert_eq!(actual, expected, "{custody:?}");
        }
    }

    #[test]
    fn terminal_receipt_persistence_uncertainty_never_claims_a_clean_local_state() {
        let upstream = CallToolResult::structured_error(json!({
            "error": {
                "code": "d1.migration_terminal_evidence_invalid",
                "message": "receipt write or sync failed after creation may have begun"
            }
        }));
        let actual = terminalize_failure(
            upstream,
            TerminalCustodyState::ActiveVerified,
            3,
            Vec::new(),
            Vec::new(),
            Value::Null,
            Value::Null,
        )
        .structured_content
        .expect("structured terminal persistence uncertainty");
        assert_eq!(actual["provider_calls"], 3);
        assert_eq!(actual["receipt_persisted"], Value::Null);
        assert_eq!(actual["local_namespace_mutations"], Value::Null);
        assert_eq!(actual["lease_retained"], json!(true));
        assert_eq!(actual["custody_status"], "retained_evidence_verified");
    }

    #[test]
    fn terminal_namespace_transition_failure_reports_current_custody_not_a_retention_guess() {
        for (custody, expected_status, expected_retained) in [
            (
                TerminalCustodyState::ActiveVerified,
                "retained_evidence_verified",
                json!(true),
            ),
            (
                TerminalCustodyState::RetiringVerified,
                "retiring_evidence_verified",
                Value::Null,
            ),
            (
                TerminalCustodyState::RetiredVerified,
                "retired_evidence_verified",
                json!(false),
            ),
            (
                TerminalCustodyState::Unverified,
                "retained_evidence_unverified",
                Value::Null,
            ),
        ] {
            let upstream = CallToolResult::structured_error(json!({
                "lease_retained": null,
                "error": {
                    "code": "d1.migration_terminal_evidence_invalid",
                    "message": "terminal namespace transition could not be completed"
                }
            }));
            let actual = terminalize_failure(upstream, custody, 2, Vec::new(), Vec::new(), 1, true)
                .structured_content
                .expect("structured terminal transition failure");
            assert_eq!(actual["provider_calls"], 2, "{custody:?}");
            assert_eq!(actual["custody_status"], expected_status, "{custody:?}");
            assert_eq!(actual["lease_retained"], expected_retained, "{custody:?}");
            assert_eq!(actual["receipt_persisted"], json!(true), "{custody:?}");
            assert_eq!(actual["local_namespace_mutations"], json!(1), "{custody:?}");
        }
    }

    #[test]
    fn detected_custody_drift_remains_unverified_after_physical_state_looks_restored() {
        let upstream = CallToolResult::structured_error(json!({
            "lease_decision": "retain",
            "lease_retained": null,
            "custody_status": "retained_evidence_unverified",
            "provider_calls": 1,
            "provider_read_lifecycle": [{"dispatch_stage": "attempted"}],
            "response_evidence": [{"response_body_sha256": "a"}],
            "error": {
                "code": "d1.migration_reconciliation_lease_changed",
                "message": "retained custody changed after the provider read"
            }
        }));
        let actual = terminalize_failure(
            upstream,
            TerminalCustodyState::ActiveVerified,
            2,
            vec![json!({"response_body_sha256": "b"})],
            vec![json!({"dispatch_stage": "received"})],
            0,
            false,
        )
        .structured_content
        .expect("structured terminalized custody drift");
        assert_eq!(actual["ok"], false, "{actual}");
        assert_eq!(actual["custody_status"], "retained_evidence_unverified");
        assert_eq!(actual["lease_retained"], Value::Null);
        assert_eq!(actual["lease_decision"], Value::Null);
        assert_eq!(actual["provider_calls"], 3);
        assert_eq!(actual["provider_mutations"], 0);
        assert_eq!(actual["local_namespace_mutations"], 0);
        assert_eq!(
            actual["error"]["code"],
            "d1.migration_reconciliation_lease_changed"
        );
    }

    #[test]
    fn exact_concurrent_retirement_replay_is_reachable_only_before_any_provider_call() {
        let zero_call_failure = CallToolResult::structured_error(json!({
            "provider_calls": 0,
            "custody_status": "inspection_failed",
            "error": {
                "code": "d1.migration_reconciliation_evidence_absent",
                "message": "active custody retired after initial inspection"
            }
        }));
        let recovered = replay_after_zero_call_prepare_failure(&zero_call_failure, || {
            Some(terminal_result(
                json!({
                    "ok": true,
                    "operation": OPERATION,
                    "dry_run": false,
                    "status": "terminal_reconciliation_already_complete",
                    "replayed": true,
                    "provider_calls": 0,
                    "provider_read_lifecycle": [],
                    "response_evidence": [],
                    "provider_mutations": 0,
                    "local_namespace_mutations": 0,
                }),
                TerminalCustodyState::RetiredVerified,
            ))
        })
        .expect("zero-call prepare race may inspect exact completed retirement");
        let recovered = recovered
            .structured_content
            .expect("structured concurrent retirement replay");
        assert_eq!(recovered["ok"], true, "{recovered}");
        assert_eq!(
            recovered["status"],
            "terminal_reconciliation_already_complete"
        );
        assert_eq!(recovered["provider_calls"], 0);
        assert_eq!(recovered["provider_mutations"], 0);
        assert_eq!(recovered["custody_status"], "retired_evidence_verified");

        let post_dispatch_failure = CallToolResult::structured_error(json!({
            "provider_calls": 1,
            "custody_status": "retained_evidence_unverified",
            "error": {
                "code": "d1.migration_reconciliation_lease_changed",
                "message": "custody changed after provider dispatch"
            }
        }));
        assert!(
            replay_after_zero_call_prepare_failure(&post_dispatch_failure, || {
                panic!("post-dispatch ambiguity must not be relabeled as zero-call replay")
            })
            .is_none()
        );
    }
}
