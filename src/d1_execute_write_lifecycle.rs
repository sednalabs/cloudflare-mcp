//! Public D1 execute-write lifecycle orchestration.
//!
//! This boundary composes exact SQL, stable provider catalog evidence,
//! reserved-relation authority, durable attempt custody, and one bounded DML
//! provider call. Ambiguous or merely provider-acknowledged attempts remain in
//! durable custody for the separately owned recovery authority.

use axum::http::request::Parts;
use rmcp::model::CallToolResult;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::cloudflare::client::CloudflareClient;
use crate::cloudflare::d1_catalog::collect_d1_catalog_provider_custody;
use crate::d1_catalog_evidence::{derive_d1_catalog_evidence_plan, prove_d1_catalog_product};
use crate::d1_dml_attempt_custody::{
    D1DmlAttemptAmbiguity, D1DmlAttemptIdentities, D1DmlAttemptPhase,
    D1DmlProviderTerminalAssertion, D1DmlProviderTerminalClassification, prepare_d1_dml_attempt,
    prepare_d1_dml_dispatch_reservation_cas, record_d1_dml_attempt_ambiguity,
    record_d1_dml_provider_terminal_assertion,
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
    parts: Option<&Parts>,
) -> CallToolResult {
    let mutation_plan = MutationPlan::new(D1_EXECUTE_WRITE_OPERATION)
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
        );
    let audit = MutationAuditSession::start(
        parts,
        D1_EXECUTE_WRITE_OPERATION,
        json!({"target_key_sha256": target.target_key_sha256()}),
        input.dry_run,
    );
    let mut result = execute_inner(client, target, input, &mutation_plan).await;
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
    emit_mutation_audit_log(&audit_record);
    result
}

async fn execute_inner(
    client: &CloudflareClient,
    target: &D1TargetIdentity,
    input: D1ExecuteWriteLifecycleInput<'_>,
    mutation_plan: &MutationPlan,
) -> CallToolResult {
    let classified = match classify_d1_dml(input.sql) {
        Ok(classified) => classified,
        Err(error) => return blocked(error.code, error.message, 0, mutation_plan, None),
    };
    let reserved_roots = match configured_reserved_roots() {
        Ok(roots) => roots,
        Err(message) => {
            return blocked(
                "d1.execute_write_reserved_roots_unconfigured",
                message,
                0,
                mutation_plan,
                None,
            );
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
            Err(result) => return result,
        }
    };
    let (catalog_plan, catalog_plan_sha256) = match derive_d1_catalog_evidence_plan(target) {
        Ok(value) => value,
        Err(error) => return blocked(error.code, error.message, 0, mutation_plan, None),
    };
    let provider_catalog = match collect_d1_catalog_provider_custody(
        client,
        target,
        &catalog_plan,
        &catalog_plan_sha256,
    )
    .await
    {
        Ok(custody) => custody,
        Err(error) => {
            return blocked(
                error.code,
                error.message,
                error.provider_calls,
                mutation_plan,
                Some(json!({
                    "catalog_provider_error": {
                        "classification": error.classification,
                        "provider_calls": error.provider_calls,
                        "complete_response_bodies": error.complete_response_bodies,
                        "retryable": error.retryable,
                    }
                })),
            );
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
        Err(error) => return blocked(error.code, error.message, 2, mutation_plan, None),
    };
    let graph = match derive_d1_reserved_relation_graph(&catalog, &reserved_roots) {
        Ok(graph) => graph,
        Err(error) => return blocked(error.code, error.message, 2, mutation_plan, None),
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
        Err(error) => return blocked(error.code, error.message, 2, mutation_plan, None),
    };
    let composition_receipt = composition.receipt();
    let identities = D1DmlAttemptIdentities {
        operation_id: input.operation_id,
        execution_attempt_id: input.execution_attempt_id,
        provider_request_id: input.provider_request_id,
    };
    let planned_attempt = match prepare_d1_dml_attempt(target, &composition, identities, None) {
        Ok(product) => product,
        Err(error) => return blocked(error.code, error.message, 2, mutation_plan, None),
    };
    let base = json!({
        "operation": D1_EXECUTE_WRITE_OPERATION,
        "execution_plan": execute_plan,
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
        return CallToolResult::structured(json!({
            "ok": true,
            "status": "planned",
            "provider_calls": 2,
            "provider_mutations": 0,
            "approved_composition_sha256_required": composition_receipt.composition_sha256,
            "evidence": base,
        }));
    }
    if input.approved_composition_sha256 != Some(composition_receipt.composition_sha256.as_str()) {
        return blocked(
            "d1.execute_write_approval_mismatch",
            "live execution requires the exact composition_sha256 returned by dry-run",
            2,
            mutation_plan,
            Some(base),
        );
    }
    let guard = guard.expect("live execution installed target guard");
    if let Err(result) = guard.revalidate() {
        return result;
    }
    execute_reserved_attempt(client, target, input, composition, guard, base).await
}

async fn execute_reserved_attempt(
    client: &CloudflareClient,
    target: &D1TargetIdentity,
    input: D1ExecuteWriteLifecycleInput<'_>,
    composition: crate::d1_exact_plan_composition::D1ExactPlanCompositionProduct,
    guard: D1TargetMutationGuard,
    base: Value,
) -> CallToolResult {
    let identities = D1DmlAttemptIdentities {
        operation_id: input.operation_id,
        execution_attempt_id: input.execution_attempt_id,
        provider_request_id: input.provider_request_id,
    };
    let initial = match prepare_d1_dml_attempt(target, &composition, identities, None) {
        Ok(product) => product,
        Err(error) => return custody_error(base, error.code, error.message, 2, None),
    };
    let binding = initial.receipt().attempt_binding_sha256.clone();
    let incumbent = match guard.read_d1_dml_attempt_state(&binding) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            if let Err(result) = guard.create_d1_dml_attempt_state(&binding, initial.state_bytes())
            {
                let _ = result;
                return custody_error(
                    base,
                    "d1.execute_write_custody_unproven",
                    "durable Prepared attempt state could not be installed exactly",
                    2,
                    Some(&binding),
                );
            }
            initial.state_bytes().to_vec()
        }
        Err(result) => {
            let _ = result;
            return custody_error(
                base,
                "d1.execute_write_custody_unproven",
                "durable attempt state could not be read exactly",
                2,
                Some(&binding),
            );
        }
    };
    let restored = match prepare_d1_dml_attempt(target, &composition, identities, Some(&incumbent))
    {
        Ok(product) => product,
        Err(error) => return custody_error(base, error.code, error.message, 2, Some(&binding)),
    };
    if restored.receipt().phase != D1DmlAttemptPhase::Prepared {
        return CallToolResult::structured_error(json!({
            "ok": false,
            "status": "reconciliation_required",
            "provider_calls": 2,
            "provider_mutations": 0,
            "custody": restored.receipt(),
            "evidence": base,
            "automatic_retry_permitted": false,
            "error": {"code": "d1.execute_write_attempt_replay", "message": "the exact attempt already crossed or reserved the provider boundary", "hint": "Use the governed recovery path; never redispatch this provider request identity."}
        }));
    }
    let reserved =
        match prepare_d1_dml_dispatch_reservation_cas(target, &composition, identities, &incumbent)
        {
            Ok(product) => product,
            Err(error) => return custody_error(base, error.code, error.message, 2, Some(&binding)),
        };
    if let Err(result) =
        guard.compare_exchange_d1_dml_attempt_state(&binding, &incumbent, reserved.state_bytes())
    {
        let _ = result;
        return custody_error(
            base,
            "d1.execute_write_custody_unproven",
            "DispatchReserved successor could not be atomically installed",
            2,
            Some(&binding),
        );
    }
    if let Err(result) = guard.revalidate() {
        let _ = result;
        return custody_error(
            base,
            "d1.execute_write_custody_unproven",
            "durable target custody changed after dispatch reservation",
            2,
            Some(&binding),
        );
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
                        3,
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
                    return custody_error(base, error.code, error.message, 3, Some(&binding));
                }
            };
            if let Err(result) = guard.compare_exchange_d1_dml_attempt_state(
                &binding,
                reserved.state_bytes(),
                asserted.state_bytes(),
            ) {
                let _ = result;
                return custody_error(
                    base,
                    "d1.execute_write_custody_unproven",
                    "authenticated provider assertion could not be durably installed",
                    3,
                    Some(&binding),
                );
            }
            CallToolResult::structured(json!({
                "ok": true,
                "status": "provider_acknowledged_reconciliation_required",
                "provider_calls": 3,
                "provider_mutations": 1,
                "outcome": outcome,
                "response_body_sha256": write.response_body_sha256,
                "response_body_size_bytes": write.response_body_size_bytes,
                "provider_lifecycle": write.lifecycle,
                "custody": asserted.receipt(),
                "evidence": base,
                "automatic_retry_permitted": false,
                "operator_guidance": "Provider acknowledgement is authenticated evidence, not terminal state authority; finalize through w13462 recovery readback."
            }))
        }
        Err(error) => {
            let calls = 2 + error.lifecycle.provider_calls();
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
                    calls,
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
                    calls,
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
    provider_calls: usize,
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
            return custody_error(
                base,
                error.code,
                error.message,
                provider_calls,
                Some(binding),
            );
        }
    };
    if let Err(result) =
        guard.compare_exchange_d1_dml_attempt_state(binding, incumbent, product.state_bytes())
    {
        let _ = result;
        return custody_error(
            base,
            "d1.execute_write_custody_unproven",
            "ambiguity evidence could not be durably installed",
            provider_calls,
            Some(binding),
        );
    }
    CallToolResult::structured_error(json!({
        "ok": false,
        "status": "reconciliation_required",
        "provider_calls": provider_calls,
        "provider_mutations": usize::from(provider_calls == 3),
        "provider_evidence": provider_evidence,
        "custody": product.receipt(),
        "evidence": base,
        "automatic_retry_permitted": false,
        "error": {"code": error_code, "message": message, "hint": "Retain custody and use the governed recovery path; do not replay this attempt."}
    }))
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
    provider_calls: usize,
    mutation_plan: &MutationPlan,
    evidence: Option<Value>,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false, "operation": D1_EXECUTE_WRITE_OPERATION, "status": "blocked",
        "provider_calls": provider_calls, "provider_mutations": 0,
        "mutation_plan": mutation_plan, "evidence": evidence,
        "automatic_retry_permitted": false,
        "error": {"code": code, "message": message, "hint": "Correct the exact authority input and repeat dry-run; no DML provider call was issued."}
    }))
}

fn custody_error(
    base: Value,
    code: &str,
    message: &str,
    provider_calls: usize,
    binding: Option<&str>,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false, "operation": D1_EXECUTE_WRITE_OPERATION, "status": "reconciliation_required",
        "provider_calls": provider_calls, "provider_mutations": usize::from(provider_calls == 3),
        "custody": {"attempt_binding_sha256": binding, "retained": binding.is_some()},
        "evidence": base, "automatic_retry_permitted": false,
        "error": {"code": code, "message": message, "hint": "Do not issue or replay a provider write; inspect durable attempt custody."}
    }))
}

fn hash_serialized<T: serde::Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("serializing exact D1 identity cannot fail");
    format!("{:x}", Sha256::digest(bytes))
}
