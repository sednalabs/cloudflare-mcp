//! Public D1 execute-write lifecycle orchestration.
//!
//! This boundary composes exact SQL, stable provider catalog evidence,
//! reserved-relation authority, durable attempt custody, and one bounded DML
//! provider call. Ambiguous or merely provider-acknowledged attempts remain in
//! durable custody for the separately owned recovery authority.

use rmcp::model::CallToolResult;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::cloudflare::client::{CloudflareClient, D1DmlWriteLifecycle};
use crate::cloudflare::d1_catalog::collect_d1_catalog_provider_custody;
use crate::d1_catalog_evidence::{derive_d1_catalog_evidence_plan, prove_d1_catalog_product};
use crate::d1_dml_attempt_custody::{
    D1DmlAttemptAmbiguity, D1DmlAttemptIdentities, D1DmlAttemptPhase,
    D1DmlProviderTerminalAssertion, D1DmlProviderTerminalClassification, prepare_d1_dml_attempt,
    prepare_d1_dml_dispatch_reservation_cas, record_d1_dml_attempt_ambiguity,
    record_d1_dml_provider_terminal_assertion, valid_d1_dml_opaque_identity,
};
use crate::d1_dml_classifier::classify_d1_dml;
use crate::d1_exact_plan_composition::compose_d1_exact_write_plan;
use crate::d1_execute_write::{
    D1_EXECUTE_WRITE_OPERATION, classify_d1_execute_write_result, derive_d1_execute_write_plan,
};
use crate::d1_migration_lease::{D1TargetMutationGuard, acquire_d1_target_mutation_guard};
use crate::d1_reserved_relation_graph::derive_d1_reserved_relation_graph;
use crate::d1_target::D1TargetIdentity;
use crate::mutation::{MutationAuditSession, MutationPlan, emit_mutation_audit_log};

pub(crate) const D1_RESERVED_RELATIONS_ENV: &str = "CLOUDFLARE_MCP_D1_RESERVED_RELATIONS";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct D1ProviderAccounting {
    completed_calls: usize,
    completed_mutations: usize,
}

impl D1ProviderAccounting {
    fn record_catalog_calls(&mut self, completed_calls: usize) {
        self.completed_calls = self.completed_calls.saturating_add(completed_calls);
    }

    fn record_dml_lifecycle(&mut self, lifecycle: D1DmlWriteLifecycle) {
        self.completed_calls = self
            .completed_calls
            .saturating_add(lifecycle.provider_calls());
        self.completed_mutations = self
            .completed_mutations
            .saturating_add(lifecycle.provider_mutations());
    }

    fn apply(self, mut result: CallToolResult) -> CallToolResult {
        if let Some(Value::Object(content)) = result.structured_content.as_mut() {
            content.insert("provider_calls".to_string(), json!(self.completed_calls));
            content.insert(
                "provider_mutations".to_string(),
                json!(self.completed_mutations),
            );
            synchronize_structured_text(&mut result);
        }
        result
    }
}

pub(crate) struct D1ExecuteWriteLifecycleInput<'a> {
    pub(crate) sql: &'a str,
    pub(crate) params: &'a [Value],
    pub(crate) operation_id: &'a str,
    pub(crate) execution_attempt_id: &'a str,
    pub(crate) provider_request_id: &'a str,
    pub(crate) approved_composition_sha256: Option<&'a str>,
    pub(crate) dry_run: bool,
    pub(crate) max_rows: usize,
}

pub(crate) async fn execute_d1_write_lifecycle(
    client: &CloudflareClient,
    target: &D1TargetIdentity,
    input: D1ExecuteWriteLifecycleInput<'_>,
    audit: MutationAuditSession,
) -> CallToolResult {
    let mutation_plan = d1_execute_write_mutation_plan();
    let mut result = execute_inner(client, target, input, &mutation_plan).await;
    finalize_d1_execute_write_result(&mut result, audit);
    result
}

pub(crate) fn finalize_d1_execute_write_zero_call_denial(
    mut result: CallToolResult,
    audit: MutationAuditSession,
) -> CallToolResult {
    let mut payload = result
        .structured_content
        .take()
        .unwrap_or_else(|| json!({"ok": false}));
    if !payload.is_object() {
        payload = json!({"ok": false, "error": {"code": "d1.execute_write_invalid_preflight", "message": "D1 write preflight failed before provider access", "hint": "Correct the exact request and repeat dry-run."}});
    }
    if let Some(content) = payload.as_object_mut() {
        content.insert("ok".to_string(), json!(false));
    }
    result.is_error = Some(true);
    result.structured_content = Some(payload);
    finalize_d1_execute_write_result(&mut result, audit);
    result
}

fn d1_execute_write_mutation_plan() -> MutationPlan {
    MutationPlan::new(D1_EXECUTE_WRITE_OPERATION)
        .step("collect_stable_catalog", false, json!({"observations": 2}))
        .step("compose_reserved_relation_authority", false, json!({}))
        .step(
            "install_dispatch_reservation",
            false,
            json!({"atomic_compare_exchange": true}),
        )
        .step(
            "submit_one_d1_dml_request",
            true,
            json!({"maximum_provider_mutations": 1}),
        )
}

fn finalize_d1_execute_write_result(result: &mut CallToolResult, audit: MutationAuditSession) {
    normalize_zero_call_denial(result);
    let is_error = result.is_error.unwrap_or(false);
    let error_code = result
        .structured_content
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(|value| value.get("code"))
        .and_then(Value::as_str);
    let audit_record = audit.finish(if is_error { "error" } else { "success" }, error_code);
    if let Some(Value::Object(content)) = result.structured_content.as_mut() {
        content.insert(
            "audit".to_string(),
            serde_json::to_value(&audit_record).expect("serializing mutation audit cannot fail"),
        );
    }
    synchronize_structured_text(result);
    emit_mutation_audit_log(&audit_record);
}

fn normalize_zero_call_denial(result: &mut CallToolResult) {
    let Some(Value::Object(content)) = result.structured_content.as_mut() else {
        return;
    };
    if content.get("ok").and_then(Value::as_bool) != Some(false)
        || content
            .get("provider_calls")
            .and_then(Value::as_u64)
            .is_some_and(|calls| calls != 0)
    {
        return;
    }
    content.insert("operation".to_string(), json!(D1_EXECUTE_WRITE_OPERATION));
    content.insert("status".to_string(), json!("blocked"));
    content.insert("provider_calls".to_string(), json!(0));
    content.insert("provider_mutations".to_string(), json!(0));
    content.insert("automatic_retry_permitted".to_string(), json!(false));
    content
        .entry("mutation_plan".to_string())
        .or_insert_with(|| json!(d1_execute_write_mutation_plan()));
    content.entry("evidence".to_string()).or_insert(Value::Null);
}

fn synchronize_structured_text(result: &mut CallToolResult) {
    if let Some(payload) = result.structured_content.as_ref() {
        result.content = vec![rmcp::model::ContentBlock::text(payload.to_string())];
    }
}

async fn execute_inner(
    client: &CloudflareClient,
    target: &D1TargetIdentity,
    input: D1ExecuteWriteLifecycleInput<'_>,
    mutation_plan: &MutationPlan,
) -> CallToolResult {
    let mut provider = D1ProviderAccounting::default();
    if let Err((code, message)) = validate_opaque_identities(&input) {
        return provider.apply(blocked(code, message, mutation_plan, None));
    }
    let classified = match classify_d1_dml(input.sql) {
        Ok(classified) => classified,
        Err(error) => {
            return provider.apply(blocked(error.code, error.message, mutation_plan, None));
        }
    };
    let reserved_roots = match configured_reserved_roots() {
        Ok(roots) => roots,
        Err(message) => {
            return provider.apply(blocked(
                "d1.execute_write_reserved_roots_unconfigured",
                message,
                mutation_plan,
                None,
            ));
        }
    };
    let execution_session_sha256 = hash_serialized(&(
        input.operation_id,
        input.execution_attempt_id,
        input.provider_request_id,
    ));
    let (execute_plan, execute_plan_sha256) = derive_d1_execute_write_plan(
        &target.account_id,
        &target.database_id,
        &target.target_key_sha256(),
        &execution_session_sha256,
        classified.statement_kind,
        input.sql,
        input.params,
        input.max_rows,
    );

    // Live execution acquires the same permanent target guard as every other
    // existing-target mutation before authority collection and keeps it
    // through provider dispatch. Dry-run performs only the two catalog reads.
    let guard = if input.dry_run {
        None
    } else {
        match acquire_d1_target_mutation_guard(
            D1_EXECUTE_WRITE_OPERATION,
            &target.account_id,
            &target.database_id,
        ) {
            Ok(guard) => Some(guard),
            Err(result) => return provider.apply(result),
        }
    };
    let (catalog_plan, catalog_plan_sha256) = match derive_d1_catalog_evidence_plan(target) {
        Ok(value) => value,
        Err(error) => {
            return provider.apply(blocked(error.code, error.message, mutation_plan, None));
        }
    };
    let provider_catalog = match collect_d1_catalog_provider_custody(
        client,
        target,
        &catalog_plan,
        &catalog_plan_sha256,
    )
    .await
    {
        Ok(custody) => {
            provider.record_catalog_calls(custody.receipt.provider_calls);
            custody
        }
        Err(error) => {
            provider.record_catalog_calls(error.provider_calls);
            return provider.apply(blocked(
                error.code,
                error.message,
                mutation_plan,
                Some(json!({
                    "catalog_provider_error": {
                        "classification": error.classification,
                        "provider_calls": error.provider_calls,
                        "complete_response_bodies": error.complete_response_bodies,
                        "retryable": error.retryable,
                    }
                })),
            ));
        }
    };
    let frames = provider_catalog.observation_frames();
    let catalog = match prove_d1_catalog_product(
        target,
        &catalog_plan,
        &catalog_plan_sha256,
        &frames[0],
        &frames[1],
    ) {
        Ok(catalog) => catalog,
        Err(error) => {
            return provider.apply(blocked(error.code, error.message, mutation_plan, None));
        }
    };
    let graph = match derive_d1_reserved_relation_graph(&catalog, &reserved_roots) {
        Ok(graph) => graph,
        Err(error) => {
            return provider.apply(blocked(error.code, error.message, mutation_plan, None));
        }
    };
    let composition = match compose_d1_exact_write_plan(
        target,
        &execute_plan,
        &execute_plan_sha256,
        &classified.relation,
        classified.form,
        &catalog,
        &graph,
    ) {
        Ok(composition) => composition,
        Err(error) => {
            return provider.apply(blocked(error.code, error.message, mutation_plan, None));
        }
    };
    let composition_receipt = composition.receipt();
    let identities = D1DmlAttemptIdentities {
        operation_id: input.operation_id,
        execution_attempt_id: input.execution_attempt_id,
        provider_request_id: input.provider_request_id,
    };
    let planned_attempt = match prepare_d1_dml_attempt(target, &composition, identities, None) {
        Ok(product) => product,
        Err(error) => {
            return provider.apply(blocked(error.code, error.message, mutation_plan, None));
        }
    };
    let base = json!({
        "operation": D1_EXECUTE_WRITE_OPERATION,
        "execution_plan": execute_plan.public_evidence(),
        "execute_plan_sha256": execute_plan_sha256,
        "catalog_provider_custody": provider_catalog.receipt,
        "catalog_evidence": catalog.receipt(),
        "reserved_relation_graph": graph.receipt(),
        "composition": composition_receipt,
        "attempt": planned_attempt.receipt(),
        "mutation_plan": mutation_plan,
        "automatic_retry_permitted": false,
    });
    if input.dry_run {
        return provider.apply(CallToolResult::structured(json!({
            "ok": true,
            "status": "planned",
            "approved_composition_sha256_required": composition_receipt.composition_sha256,
            "evidence": base,
        })));
    }
    if input.approved_composition_sha256 != Some(composition_receipt.composition_sha256.as_str()) {
        return provider.apply(blocked(
            "d1.execute_write_approval_mismatch",
            "live execution requires the exact composition_sha256 returned by dry-run",
            mutation_plan,
            Some(base),
        ));
    }
    let guard = guard.expect("live execution installed target guard");
    if let Err(result) = guard.revalidate() {
        return provider.apply(result);
    }
    execute_reserved_attempt(client, target, input, composition, guard, base, provider).await
}

fn validate_opaque_identities(
    input: &D1ExecuteWriteLifecycleInput<'_>,
) -> Result<(), (&'static str, &'static str)> {
    let identities = [
        input.operation_id,
        input.execution_attempt_id,
        input.provider_request_id,
    ];
    if identities
        .iter()
        .any(|value| !valid_d1_dml_opaque_identity(value))
    {
        return Err((
            "d1.execute_write_opaque_identity_invalid",
            "operation, execution-attempt and provider-request identities must each be 16..=128 ASCII letters, digits, '.', '_', ':' or '-'",
        ));
    }
    if identities
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != 3
    {
        return Err((
            "d1.execute_write_opaque_identity_duplicate",
            "operation, execution-attempt and provider-request identities must be pairwise distinct",
        ));
    }
    Ok(())
}

async fn execute_reserved_attempt(
    client: &CloudflareClient,
    target: &D1TargetIdentity,
    input: D1ExecuteWriteLifecycleInput<'_>,
    composition: crate::d1_exact_plan_composition::D1ExactPlanCompositionProduct,
    guard: D1TargetMutationGuard,
    base: Value,
    mut provider: D1ProviderAccounting,
) -> CallToolResult {
    let identities = D1DmlAttemptIdentities {
        operation_id: input.operation_id,
        execution_attempt_id: input.execution_attempt_id,
        provider_request_id: input.provider_request_id,
    };
    let initial = match prepare_d1_dml_attempt(target, &composition, identities, None) {
        Ok(product) => product,
        Err(error) => return provider.apply(custody_error(base, error.code, error.message, None)),
    };
    let binding = initial.receipt().attempt_binding_sha256.clone();
    let incumbent = match guard.read_d1_dml_attempt_state(&binding) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            if let Err(result) = guard.create_d1_dml_attempt_state(&binding, initial.state_bytes())
            {
                let _ = result;
                return provider.apply(custody_error(
                    base,
                    "d1.execute_write_custody_unproven",
                    "durable Prepared attempt state could not be installed exactly",
                    Some(&binding),
                ));
            }
            initial.state_bytes().to_vec()
        }
        Err(result) => {
            let _ = result;
            return provider.apply(custody_error(
                base,
                "d1.execute_write_custody_unproven",
                "durable attempt state could not be read exactly",
                Some(&binding),
            ));
        }
    };
    let restored = match prepare_d1_dml_attempt(target, &composition, identities, Some(&incumbent))
    {
        Ok(product) => product,
        Err(error) => {
            return provider.apply(custody_error(
                base,
                error.code,
                error.message,
                Some(&binding),
            ));
        }
    };
    if restored.receipt().phase != D1DmlAttemptPhase::Prepared {
        return provider.apply(CallToolResult::structured_error(json!({
            "ok": false,
            "status": "reconciliation_required",
            "custody": restored.receipt(),
            "evidence": base,
            "automatic_retry_permitted": false,
            "error": {"code": "d1.execute_write_attempt_replay", "message": "the exact attempt already crossed or reserved the provider boundary", "hint": "Use the governed recovery path; never redispatch this provider request identity."}
        })));
    }
    let reserved =
        match prepare_d1_dml_dispatch_reservation_cas(target, &composition, identities, &incumbent)
        {
            Ok(product) => product,
            Err(error) => {
                return provider.apply(custody_error(
                    base,
                    error.code,
                    error.message,
                    Some(&binding),
                ));
            }
        };
    if let Err(result) =
        guard.compare_exchange_d1_dml_attempt_state(&binding, &incumbent, reserved.state_bytes())
    {
        let _ = result;
        return provider.apply(custody_error(
            base,
            "d1.execute_write_custody_unproven",
            "DispatchReserved successor could not be atomically installed",
            Some(&binding),
        ));
    }
    if let Err(result) = guard.revalidate() {
        let _ = result;
        return provider.apply(custody_error(
            base,
            "d1.execute_write_custody_unproven",
            "durable target custody changed after dispatch reservation",
            Some(&binding),
        ));
    }
    match client
        .execute_d1_dml_write(
            &target.account_id,
            &target.database_id,
            input.provider_request_id,
            input.sql,
            input.params,
        )
        .await
    {
        Ok(write) => {
            provider.record_dml_lifecycle(write.lifecycle);
            let outcome = match classify_d1_execute_write_result(
                composition.plan().statement_kind,
                &write.result,
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    return persist_ambiguity(
                        &guard,
                        target,
                        &composition,
                        identities,
                        &binding,
                        reserved.state_bytes(),
                        D1DmlAttemptAmbiguity::ResponseContradictory,
                        base,
                        error.code,
                        error.message,
                        provider,
                        Some(
                            json!({"response_body_sha256": write.response_body_sha256, "response_body_size_bytes": write.response_body_size_bytes, "provider_lifecycle": write.lifecycle}),
                        ),
                    );
                }
            };
            let classification = if outcome.zero_change {
                D1DmlProviderTerminalClassification::SucceededUnchanged
            } else {
                D1DmlProviderTerminalClassification::SucceededChanged
            };
            let asserted = match record_d1_dml_provider_terminal_assertion(
                target,
                &composition,
                identities,
                reserved.state_bytes(),
                D1DmlProviderTerminalAssertion {
                    classification,
                    evidence_sha256: &write.response_body_sha256,
                },
            ) {
                Ok(product) => product,
                Err(error) => {
                    return provider.apply(custody_error(
                        base,
                        error.code,
                        error.message,
                        Some(&binding),
                    ));
                }
            };
            if let Err(result) = guard.compare_exchange_d1_dml_attempt_state(
                &binding,
                reserved.state_bytes(),
                asserted.state_bytes(),
            ) {
                let _ = result;
                return provider.apply(custody_error(
                    base,
                    "d1.execute_write_custody_unproven",
                    "authenticated provider assertion could not be durably installed",
                    Some(&binding),
                ));
            }
            provider.apply(CallToolResult::structured(json!({
                "ok": true,
                "status": "provider_acknowledged_reconciliation_required",
                "outcome": outcome,
                "response_body_sha256": write.response_body_sha256,
                "response_body_size_bytes": write.response_body_size_bytes,
                "provider_lifecycle": write.lifecycle,
                "custody": asserted.receipt(),
                "evidence": base,
                "automatic_retry_permitted": false,
                "operator_guidance": "Provider acknowledgement is authenticated evidence, not terminal state authority; finalize through w13462 recovery readback."
            })))
        }
        Err(error) => {
            provider.record_dml_lifecycle(error.lifecycle);
            if error.lifecycle.provider_calls() == 0 {
                // Reservation is already durable. Even a pre-dispatch adapter
                // failure is never redispatched by this invocation.
                persist_ambiguity(
                    &guard,
                    target,
                    &composition,
                    identities,
                    &binding,
                    reserved.state_bytes(),
                    D1DmlAttemptAmbiguity::ResponseMissing,
                    base,
                    &error.error.code,
                    "provider dispatch did not produce terminal authenticated evidence",
                    provider,
                    Some(json!({"provider_lifecycle": error.lifecycle})),
                )
            } else {
                persist_ambiguity(
                    &guard,
                    target,
                    &composition,
                    identities,
                    &binding,
                    reserved.state_bytes(),
                    D1DmlAttemptAmbiguity::TransportUncertain,
                    base,
                    &error.error.code,
                    "provider attempt outcome was ambiguous",
                    provider,
                    Some(
                        json!({"response_body_sha256": error.response_body_sha256, "response_body_size_bytes": error.response_body_size_bytes, "provider_lifecycle": error.lifecycle, "provider_error": error.provider_error}),
                    ),
                )
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_ambiguity(
    guard: &D1TargetMutationGuard,
    target: &D1TargetIdentity,
    composition: &crate::d1_exact_plan_composition::D1ExactPlanCompositionProduct,
    identities: D1DmlAttemptIdentities<'_>,
    binding: &str,
    incumbent: &[u8],
    ambiguity: D1DmlAttemptAmbiguity,
    base: Value,
    error_code: &str,
    message: &str,
    provider: D1ProviderAccounting,
    provider_evidence: Option<Value>,
) -> CallToolResult {
    let product = match record_d1_dml_attempt_ambiguity(
        target,
        composition,
        identities,
        incumbent,
        ambiguity,
    ) {
        Ok(product) => product,
        Err(error) => {
            return provider.apply(custody_error(
                base,
                error.code,
                error.message,
                Some(binding),
            ));
        }
    };
    if let Err(result) =
        guard.compare_exchange_d1_dml_attempt_state(binding, incumbent, product.state_bytes())
    {
        let _ = result;
        return provider.apply(custody_error(
            base,
            "d1.execute_write_custody_unproven",
            "ambiguity evidence could not be durably installed",
            Some(binding),
        ));
    }
    provider.apply(CallToolResult::structured_error(json!({
        "ok": false,
        "status": "reconciliation_required",
        "provider_evidence": provider_evidence,
        "custody": product.receipt(),
        "evidence": base,
        "automatic_retry_permitted": false,
        "error": {"code": error_code, "message": message, "hint": "Retain custody and use the governed recovery path; do not replay this attempt."}
    })))
}

fn configured_reserved_roots() -> Result<Vec<String>, &'static str> {
    let value = std::env::var(D1_RESERVED_RELATIONS_ENV).map_err(
        |_| "configured reserved D1 relation roots are required before planning or execution",
    )?;
    let roots = value
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect::<Vec<_>>();
    if roots.is_empty() || roots.iter().any(|value| value.is_empty()) {
        return Err("configured reserved D1 relation roots were empty or malformed");
    }
    Ok(roots)
}

fn blocked(
    code: &str,
    message: &str,
    mutation_plan: &MutationPlan,
    evidence: Option<Value>,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false, "operation": D1_EXECUTE_WRITE_OPERATION, "status": "blocked",
        "mutation_plan": mutation_plan, "evidence": evidence,
        "automatic_retry_permitted": false,
        "error": {"code": code, "message": message, "hint": "Correct the exact authority input and repeat dry-run; no DML provider call was issued."}
    }))
}

fn custody_error(base: Value, code: &str, message: &str, binding: Option<&str>) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false, "operation": D1_EXECUTE_WRITE_OPERATION, "status": "reconciliation_required",
        "custody": {"attempt_binding_sha256": binding, "retained": binding.is_some()},
        "evidence": base, "automatic_retry_permitted": false,
        "error": {"code": code, "message": message, "hint": "Do not issue or replay a provider write; inspect durable attempt custody."}
    }))
}

fn hash_serialized<T: serde::Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("serializing exact D1 identity cannot fail");
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lifecycle(dispatch_stage: &'static str) -> D1DmlWriteLifecycle {
        D1DmlWriteLifecycle {
            dispatch_stage,
            response_stage: "not_received",
            body_stage: "not_read",
            http_status: None,
        }
    }

    fn phase_result(phase: &str, status: &str) -> CallToolResult {
        CallToolResult::structured_error(json!({
            "ok": false,
            "phase": phase,
            "status": status,
            "provider_calls": 999,
            "provider_mutations": 999,
        }))
    }

    #[test]
    fn provider_accounting_stamps_exact_whole_results_for_every_exit_phase() {
        let cases = [
            ("zero_call_preflight", 0, None, "blocked", 0, 0),
            ("first_catalog_read_failed", 1, None, "blocked", 1, 0),
            ("two_catalog_reads", 2, None, "planned", 2, 0),
            ("guard_revalidation_failed", 2, None, "blocked", 2, 0),
            ("cas_install_failed", 2, None, "blocked", 2, 0),
            (
                "dml_predispatch_failed",
                2,
                Some("pre_dispatch"),
                "reconciliation_required",
                2,
                0,
            ),
            (
                "dml_response_lost",
                2,
                Some("attempted"),
                "reconciliation_required",
                3,
                1,
            ),
            (
                "zero_change_acknowledged",
                2,
                Some("attempted"),
                "provider_acknowledged_reconciliation_required",
                3,
                1,
            ),
            (
                "terminal_response",
                2,
                Some("attempted"),
                "provider_acknowledged_reconciliation_required",
                3,
                1,
            ),
        ];

        for (phase, catalog_calls, dml_stage, status, calls, mutations) in cases {
            let mut accounting = D1ProviderAccounting::default();
            accounting.record_catalog_calls(catalog_calls);
            if let Some(stage) = dml_stage {
                accounting.record_dml_lifecycle(lifecycle(stage));
            }
            let result = accounting.apply(phase_result(phase, status));
            assert_eq!(
                result.structured_content,
                Some(json!({
                    "ok": false,
                    "phase": phase,
                    "status": status,
                    "provider_calls": calls,
                    "provider_mutations": mutations,
                })),
                "{phase}"
            );
            let content = serde_json::to_value(&result.content[0])
                .expect("serialize accounted result content");
            let text = content["text"].as_str().expect("accounted result text");
            assert_eq!(
                serde_json::from_str::<Value>(text).expect("accounted result text JSON"),
                result
                    .structured_content
                    .clone()
                    .expect("accounted payload"),
                "{phase}"
            );
        }
    }

    #[test]
    fn opaque_identity_preflight_matches_custody_grammar_and_requires_distinct_values() {
        fn input<'a>(
            operation_id: &'a str,
            execution_attempt_id: &'a str,
            provider_request_id: &'a str,
        ) -> D1ExecuteWriteLifecycleInput<'a> {
            D1ExecuteWriteLifecycleInput {
                sql: "UPDATE example SET enabled = 1",
                params: &[],
                operation_id,
                execution_attempt_id,
                provider_request_id,
                approved_composition_sha256: None,
                dry_run: true,
                max_rows: 100,
            }
        }

        assert_eq!(
            validate_opaque_identities(&input(
                "operation-fixture-0001",
                "attempt-fixture-0001",
                "provider-fixture-0001"
            )),
            Ok(())
        );
        let minimum = "A".repeat(16);
        let maximum = "z".repeat(128);
        assert_eq!(
            validate_opaque_identities(&input(&minimum, &maximum, "provider-fixture-0001")),
            Ok(())
        );
        for invalid in [
            "short",
            "identity has space",
            "identity-with-control\n",
            "identity-with-nonascii-é",
            "operation!fixture-0001",
            "operation/fixture-0001",
            "operation@fixture-0001",
        ] {
            assert_eq!(
                validate_opaque_identities(&input(
                    invalid,
                    "attempt-fixture-0001",
                    "provider-fixture-0001"
                )),
                Err((
                    "d1.execute_write_opaque_identity_invalid",
                    "operation, execution-attempt and provider-request identities must each be 16..=128 ASCII letters, digits, '.', '_', ':' or '-'"
                ))
            );
        }
        for invalid in ["A".repeat(15), "z".repeat(129)] {
            assert_eq!(
                validate_opaque_identities(&input(
                    &invalid,
                    "attempt-fixture-0001",
                    "provider-fixture-0001"
                ))
                .map_err(|(code, _)| code),
                Err("d1.execute_write_opaque_identity_invalid")
            );
        }
        assert_eq!(
            validate_opaque_identities(&input(
                "same-identity-fixture-0001",
                "same-identity-fixture-0001",
                "provider-fixture-0001"
            )),
            Err((
                "d1.execute_write_opaque_identity_duplicate",
                "operation, execution-attempt and provider-request identities must be pairwise distinct"
            ))
        );
    }
}
