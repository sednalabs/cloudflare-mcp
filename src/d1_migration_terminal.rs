//! Approval-bound terminal recovery for retained D1 migration manifests.
//!
//! This boundary never retries or submits provider writes. It re-proves one
//! exact retained manifest with primary-current reads, creates one canonical
//! local receipt without replacement, re-proves the same snapshot, and only
//! then retires the retained lease under the permanent target guard.

use rmcp::model::CallToolResult;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::d1_migration_lease::{
    D1TerminalReconciliationReceipt, inspect_terminal_d1_migration_lease,
};
use crate::d1_migration_reconciliation::{
    D1MigrationStateExpectation, prepare_d1_migration_reconciliation,
    refresh_d1_migration_reconciliation,
};
use crate::server::CloudflareMcp;
use crate::tools::{D1MigrationManifestEntry, sha256_bytes_hex};

const OPERATION: &str = "d1_finalize_migration_reconciliation";

pub(crate) fn contextualize_terminal_semantic_error(result: CallToolResult) -> CallToolResult {
    terminalize_failure(result, 0, Vec::new(), Vec::new(), 0, false)
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
    );
    if !dry_run && approved_terminal_plan_sha256 != Some(terminal_plan_sha256.as_str()) {
        return terminal_error(
            "d1.migration_terminal_plan_mismatch",
            "approved_terminal_plan_sha256 does not match the exact pre-existing terminal plan",
            0,
            Vec::new(),
            Vec::new(),
            0,
            false,
        );
    }
    let receipt = D1TerminalReconciliationReceipt {
        version: 1,
        operation: OPERATION.to_string(),
        target_key_sha256,
        lease_nonce: lease_nonce.to_string(),
        lease_payload_sha256: lease_payload_sha256.to_string(),
        approved_apply_plan_sha256: approved_plan_sha256.to_string(),
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

    let initial_lease = match inspect_terminal_d1_migration_lease(
        account_id,
        database_id,
        family,
        approved_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
    ) {
        Ok(lease) => lease,
        Err(result) => return terminalize_failure(result, 0, Vec::new(), Vec::new(), 0, false),
    };
    if initial_lease.is_retired() {
        let receipt_evidence = match initial_lease.terminal_receipt_state(&receipt) {
            Ok(Some(evidence)) => evidence,
            Ok(None) => {
                return terminal_error(
                    "d1.migration_terminal_receipt_absent",
                    "terminal retirement exists without its exact terminal receipt",
                    0,
                    Vec::new(),
                    Vec::new(),
                    0,
                    false,
                );
            }
            Err(result) => {
                return terminalize_failure(result, 0, Vec::new(), Vec::new(), 0, false);
            }
        };
        return CallToolResult::structured(json!({
            "ok": true,
            "operation": OPERATION,
            "dry_run": dry_run,
            "status": "terminal_reconciliation_already_complete",
            "replayed": true,
            "terminal_plan_sha256": terminal_plan_sha256,
            "terminal_receipt_sha256": receipt_evidence.payload_sha256,
            "lease_decision": "retired",
            "lease_retained": false,
            "provider_calls": 0,
            "provider_read_lifecycle": [],
            "response_evidence": [],
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
        }));
    }
    let initial_receipt_preexisted = match initial_lease.terminal_receipt_state(&receipt) {
        Ok(Some(_)) => true,
        Ok(None) if initial_lease.identity.namespace == "active" => false,
        Ok(None) => {
            return terminal_error(
                "d1.migration_terminal_receipt_absent",
                "terminal retirement began without its exact durable terminal receipt",
                0,
                Vec::new(),
                Vec::new(),
                0,
                false,
            );
        }
        Err(result) => {
            return terminalize_failure(result, 0, Vec::new(), Vec::new(), 0, false);
        }
    };
    let recovering_exact_retiring_receipt =
        initial_receipt_preexisted && initial_lease.identity.namespace == "retiring";
    drop(initial_lease);

    let mut proof = match prepare_d1_migration_reconciliation(
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
    )
    .await
    {
        Ok(proof) => proof,
        Err(result) => return terminalize_failure(result, 0, Vec::new(), Vec::new(), 0, false),
    };
    let mut response_evidence = proof.response_evidence();
    let mut lifecycle = proof.provider_read_lifecycle();
    let exact_active_plan_matches = recovering_exact_retiring_receipt
        && proof.plan_sha256_for_namespace(
            account_id,
            database_id,
            family,
            migrations_table,
            manifest,
            "active",
        ) == expected_reconciliation_plan_sha256;
    if (proof.reconciliation_plan_sha256 != expected_reconciliation_plan_sha256
        && !exact_active_plan_matches)
        || proof.expectation_proof_sha256 != expected_expectation_proof_sha256
        || proof.query_sha256() != expected_query_sha256
        || proof.canonical_snapshot_sha256 != expected_canonical_snapshot_sha256
        || proof.outcome != expected_outcome
        || proof.original_prefix_length != expected_original_prefix_length
        || proof.current_prefix_length != expected_current_prefix_length
    {
        return terminal_error(
            "d1.migration_terminal_approved_evidence_mismatch",
            "fresh retained-manifest proof does not match every independently approved expectation, query, snapshot, outcome, and prefix",
            2,
            response_evidence,
            lifecycle,
            0,
            false,
        );
    }

    if dry_run {
        return CallToolResult::structured(json!({
            "ok": true,
            "operation": OPERATION,
            "dry_run": true,
            "status": "terminal_reconciliation_plan_ready",
            "terminal_plan_sha256": terminal_plan_sha256,
            "approved_evidence": {
                "reconciliation_plan_sha256": expected_reconciliation_plan_sha256,
                "expectation_proof_sha256": expected_expectation_proof_sha256,
                "query_sha256": expected_query_sha256,
                "canonical_snapshot_sha256": expected_canonical_snapshot_sha256,
                "terminal_request_sha256": terminal_request_sha256,
                "terminal_attempt_sha256": terminal_attempt_sha256,
            },
            "lease_decision": "retain",
            "lease_retained": true,
            "provider_calls": 2,
            "provider_read_lifecycle": lifecycle,
            "response_evidence": response_evidence,
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "next_action": "independently approve this exact terminal_plan_sha256 before a live call",
        }));
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
            return terminalize_failure(result, 2, response_evidence, lifecycle, 0, false);
        }
    };
    response_evidence.push(before_receipt.response_evidence);
    lifecycle.push(before_receipt.lifecycle);

    let (receipt_evidence, receipt_created) = match proof.lease.persist_terminal_receipt(&receipt) {
        Ok(receipt) => receipt,
        Err(result) => {
            return terminalize_failure(result, 3, response_evidence, lifecycle, 0, false);
        }
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
            return terminalize_failure(
                result,
                3,
                response_evidence,
                lifecycle,
                local_mutations,
                true,
            );
        }
    };
    response_evidence.push(before_retirement.response_evidence);
    lifecycle.push(before_retirement.lifecycle);

    let retired_now = match proof.lease.retire_after_terminal_receipt(&receipt_evidence) {
        Ok(retired) => retired,
        Err(result) => {
            return terminalize_failure(
                result,
                4,
                response_evidence,
                lifecycle,
                local_mutations,
                true,
            );
        }
    };
    CallToolResult::structured(json!({
        "ok": true,
        "operation": OPERATION,
        "dry_run": false,
        "status": "terminal_reconciliation_complete",
        "replayed": !receipt_created && !retired_now,
        "terminal_plan_sha256": terminal_plan_sha256,
        "terminal_receipt_sha256": receipt_evidence.payload_sha256,
        "approved_evidence": {
            "reconciliation_plan_sha256": expected_reconciliation_plan_sha256,
            "expectation_proof_sha256": expected_expectation_proof_sha256,
            "query_sha256": expected_query_sha256,
            "canonical_snapshot_sha256": expected_canonical_snapshot_sha256,
            "terminal_request_sha256": terminal_request_sha256,
            "terminal_attempt_sha256": terminal_attempt_sha256,
        },
        "lease_decision": "retired",
        "lease_retained": false,
        "provider_calls": 4,
        "provider_read_lifecycle": lifecycle,
        "response_evidence": response_evidence,
        "provider_mutations": 0,
        "local_namespace_mutations": local_mutations + usize::from(retired_now),
    }))
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
        || !matches!(
            expected_outcome,
            "not_committed" | "partial_state_converged" | "full_state_converged"
        )
        || expected_current_prefix_length < expected_original_prefix_length
        || (!dry_run
            && approved_terminal_plan_sha256.is_none_or(|value| !valid_lower_sha256(value)))
    {
        return Err(terminal_error(
            "d1.migration_terminal_request_invalid",
            "terminal reconciliation requires canonical distinct request/attempt digests, exact approved evidence, a valid outcome/prefix relationship, and a live approval pin",
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
    sha256_bytes_hex(&serde_json::to_vec(&plan).expect("terminal plan serialization is infallible"))
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn terminalize_failure(
    result: CallToolResult,
    completed_provider_calls: usize,
    prior_response_evidence: Vec<Value>,
    prior_lifecycle: Vec<Value>,
    local_namespace_mutations: usize,
    receipt_persisted: bool,
) -> CallToolResult {
    let mut content = result.structured_content.unwrap_or_else(|| {
        json!({"error": {"code": "d1.migration_terminal_failed", "message": "terminal reconciliation failed closed"}})
    });
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
        map.insert("lease_decision".to_string(), json!("retain"));
        map.insert("lease_retained".to_string(), json!(true));
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
fn terminal_error(
    code: &'static str,
    message: &'static str,
    provider_calls: usize,
    response_evidence: Vec<Value>,
    lifecycle: Vec<Value>,
    local_namespace_mutations: usize,
    receipt_persisted: bool,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": OPERATION,
        "status": "reconciliation_required",
        "retry_decision": "do_not_retry_same_attempt",
        "lease_decision": "retain",
        "lease_retained": true,
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
    }))
}
