//! Exact D1 write-plan composition against reserved-relation authority.
//!
//! This pure boundary accepts only an exact classified write plan, the opaque
//! verified catalog product, and the opaque reserved-relation graph product.
//! It binds the exact classified relation and closed operation form, then
//! requires every effective primitive decision to be `Allow`.
//!
//! This module does not parse SQL, accept caller JSON, issue provider requests,
//! expose a tool route, admit a mutation, or authorize execution. Its inputs
//! must come from the separately owned exact classifier and evidence stages.

use std::collections::BTreeSet;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::d1_catalog_evidence::{
    D1_CATALOG_EVIDENCE_OPERATION, D1CatalogEvidenceProduct, D1CatalogEvidenceReceipt,
};
use crate::d1_execute_write::{
    D1_EXECUTE_WRITE_OPERATION, D1ExecuteWritePlan, D1WriteStatementKind,
};
use crate::d1_reserved_relation_graph::{
    D1_RESERVED_RELATION_GRAPH_OPERATION, D1RelationWriteOperation, D1ReservedRelationDecision,
    D1ReservedRelationGraphProduct, D1ReservedRelationGraphReceipt, D1WriteOperationForm,
    required_relation_write_operations,
};
use crate::d1_target::{D1TargetIdentity, normalize_d1_target};

pub(crate) const D1_EXACT_PLAN_COMPOSITION_OPERATION: &str = "d1_exact_write_plan_composition";

const COMPOSITION_VERSION: u8 = 1;
const REQUIRED_EXECUTE_PLAN_VERSION: u8 = 2;
const REQUIRED_CATALOG_VERSION: u8 = 5;
const REQUIRED_GRAPH_VERSION: u8 = 3;
const MAX_WRITE_ROWS: usize = 1_000;
const MAX_RELATION_IDENTITY_BYTES: usize = 255;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1ExactPlanCompositionReceipt {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) target_key_sha256: String,
    pub(crate) execute_plan_sha256: String,
    pub(crate) catalog_snapshot_sha256: String,
    pub(crate) catalog_receipt_sha256: String,
    pub(crate) graph_sha256: String,
    pub(crate) graph_decision_sha256: String,
    pub(crate) graph_receipt_sha256: String,
    pub(crate) classified_relation_sha256: String,
    pub(crate) classified_form_sha256: String,
    pub(crate) effective_primitive_sha256: String,
    pub(crate) effective_primitive_count: usize,
    pub(crate) allow_decision_count: usize,
    pub(crate) effective_decision_sha256: String,
    pub(crate) composition_sha256: String,
}

/// Stable catalog authority committed into an approval composition.
///
/// The full catalog receipt is validated before this projection is built. Its
/// observation-pair digest deliberately proves fresh physical read custody and
/// therefore changes on every dry-run/live collection. Approval authority must
/// instead converge when the exact catalog query, normalized snapshot, shape,
/// caps, and stable-read cardinality are unchanged.
#[derive(Serialize)]
struct D1StableCatalogAuthorityReceipt<'a> {
    version: u8,
    operation: &'static str,
    target_key_sha256: &'a str,
    query_plan_sha256: &'a str,
    query_sha256: &'a str,
    projection_version: u8,
    catalog_snapshot_sha256: &'a str,
    catalog_row_count: usize,
    schema_physical_row_count: usize,
    relation_fact_count: usize,
    trigger_owner_fact_count: usize,
    schema_auxiliary_fact_count: usize,
    schema_blocker_fact_count: usize,
    foreign_key_fact_count: usize,
    foreign_key_blocker_fact_count: usize,
    conservative_blocker_count: usize,
    stable_primary_observations: u8,
    provider_row_cap: usize,
    provider_byte_cap: usize,
    response_body_sizes: [usize; 2],
}

/// Opaque pure composition product. Relation identity and the classified plan
/// remain internal; only the aggregate-safe receipt is serializable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1ExactPlanCompositionProduct {
    receipt: D1ExactPlanCompositionReceipt,
    plan: D1ExecuteWritePlan,
    classified_relation: String,
    classified_form: D1WriteOperationForm,
    effective_primitives: Vec<D1RelationWriteOperation>,
}

impl D1ExactPlanCompositionProduct {
    pub(crate) fn receipt(&self) -> &D1ExactPlanCompositionReceipt {
        &self.receipt
    }

    pub(crate) fn plan(&self) -> &D1ExecuteWritePlan {
        &self.plan
    }

    pub(crate) fn classified_relation(&self) -> &str {
        &self.classified_relation
    }

    pub(crate) fn classified_form(&self) -> D1WriteOperationForm {
        self.classified_form
    }

    pub(crate) fn effective_primitives(&self) -> &[D1RelationWriteOperation] {
        &self.effective_primitives
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1ExactPlanCompositionClassification {
    TargetIdentityInvalid,
    PlanDigestInvalid,
    PlanProductMismatch,
    PlanTargetMismatch,
    PlanFormMismatch,
    ClassifiedRelationInvalid,
    CatalogProductMismatch,
    CatalogProjectionUnsupported,
    GraphProductMismatch,
    GraphProjectionUnsupported,
    CompoundWriteUnsupported,
    PrimitiveExpansionMismatch,
    PrimitiveDuplicate,
    GraphDecisionMissing,
    GraphDecisionDenied,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1ExactPlanCompositionError {
    pub(crate) code: &'static str,
    pub(crate) classification: D1ExactPlanCompositionClassification,
    pub(crate) message: &'static str,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compose_d1_exact_write_plan(
    target: &D1TargetIdentity,
    plan: &D1ExecuteWritePlan,
    execute_plan_sha256: &str,
    classified_relation: &str,
    classified_form: D1WriteOperationForm,
    catalog: &D1CatalogEvidenceProduct,
    graph: &D1ReservedRelationGraphProduct,
) -> Result<D1ExactPlanCompositionProduct, D1ExactPlanCompositionError> {
    let primitives = required_relation_write_operations(classified_form).map_err(|_| {
        composition_error(
            D1ExactPlanCompositionClassification::CompoundWriteUnsupported,
            "classified write form is outside the closed primitive expansion contract",
        )
    })?;
    compose_from_verified_parts(
        target,
        plan,
        execute_plan_sha256,
        classified_relation,
        classified_form,
        catalog.receipt(),
        graph.receipt(),
        primitives,
        |operation| graph.decision_for(classified_relation, operation),
    )
}

#[allow(clippy::too_many_arguments)]
fn compose_from_verified_parts<F>(
    target: &D1TargetIdentity,
    plan: &D1ExecuteWritePlan,
    execute_plan_sha256: &str,
    classified_relation: &str,
    classified_form: D1WriteOperationForm,
    catalog_receipt: &D1CatalogEvidenceReceipt,
    graph_receipt: &D1ReservedRelationGraphReceipt,
    primitives: &[D1RelationWriteOperation],
    mut decision_for: F,
) -> Result<D1ExactPlanCompositionProduct, D1ExactPlanCompositionError>
where
    F: FnMut(D1RelationWriteOperation) -> Option<D1ReservedRelationDecision>,
{
    validate_target(target)?;
    validate_plan(target, plan, execute_plan_sha256, classified_form)?;
    let canonical_relation = validate_relation(classified_relation)?;
    validate_catalog_receipt(target, catalog_receipt)?;
    validate_graph_receipt(catalog_receipt, graph_receipt)?;
    if primitives.iter().copied().collect::<BTreeSet<_>>().len() != primitives.len() {
        return Err(composition_error(
            D1ExactPlanCompositionClassification::PrimitiveDuplicate,
            "effective primitive expansion contained a duplicate operation",
        ));
    }
    validate_primitive_expansion(classified_form, primitives)?;

    let mut decisions = Vec::with_capacity(primitives.len());
    for operation in primitives {
        let decision = decision_for(*operation).ok_or_else(|| {
            composition_error(
                D1ExactPlanCompositionClassification::GraphDecisionMissing,
                "reserved-relation graph lacked one required primitive decision",
            )
        })?;
        if decision != D1ReservedRelationDecision::Allow {
            return Err(composition_error(
                D1ExactPlanCompositionClassification::GraphDecisionDenied,
                "reserved-relation graph denied one required primitive decision",
            ));
        }
        decisions.push((*operation, decision));
    }

    let target_key_sha256 = target.target_key_sha256();
    let catalog_receipt_sha256 = hash_stable_catalog_authority(catalog_receipt);
    let graph_receipt_sha256 = hash_serialized(graph_receipt);
    let classified_relation_sha256 = hash_bytes(canonical_relation.as_bytes());
    let classified_form_sha256 = hash_serialized(&form_label(classified_form));
    let effective_primitive_sha256 = hash_serialized(primitives);
    let effective_decision_sha256 = hash_serialized(&(
        classified_relation_sha256.as_str(),
        classified_form_sha256.as_str(),
        decisions.as_slice(),
    ));
    let composition_sha256 = hash_serialized(&(
        COMPOSITION_VERSION,
        D1_EXACT_PLAN_COMPOSITION_OPERATION,
        target_key_sha256.as_str(),
        execute_plan_sha256,
        catalog_receipt.catalog_snapshot_sha256.as_str(),
        catalog_receipt_sha256.as_str(),
        graph_receipt.graph_sha256.as_str(),
        graph_receipt.decision_sha256.as_str(),
        graph_receipt_sha256.as_str(),
        classified_relation_sha256.as_str(),
        classified_form_sha256.as_str(),
        effective_primitive_sha256.as_str(),
        effective_decision_sha256.as_str(),
    ));

    let receipt = D1ExactPlanCompositionReceipt {
        version: COMPOSITION_VERSION,
        operation: D1_EXACT_PLAN_COMPOSITION_OPERATION,
        target_key_sha256,
        execute_plan_sha256: execute_plan_sha256.to_string(),
        catalog_snapshot_sha256: catalog_receipt.catalog_snapshot_sha256.clone(),
        catalog_receipt_sha256,
        graph_sha256: graph_receipt.graph_sha256.clone(),
        graph_decision_sha256: graph_receipt.decision_sha256.clone(),
        graph_receipt_sha256,
        classified_relation_sha256,
        classified_form_sha256,
        effective_primitive_sha256,
        effective_primitive_count: primitives.len(),
        allow_decision_count: decisions.len(),
        effective_decision_sha256,
        composition_sha256,
    };
    Ok(D1ExactPlanCompositionProduct {
        receipt,
        plan: plan.clone(),
        classified_relation: canonical_relation,
        classified_form,
        effective_primitives: primitives.to_vec(),
    })
}

fn validate_target(target: &D1TargetIdentity) -> Result<(), D1ExactPlanCompositionError> {
    let normalized =
        normalize_d1_target(&target.account_id, &target.database_id).map_err(|_| {
            composition_error(
                D1ExactPlanCompositionClassification::TargetIdentityInvalid,
                "D1 target identity was not exact canonical input",
            )
        })?;
    if &normalized != target {
        return Err(composition_error(
            D1ExactPlanCompositionClassification::TargetIdentityInvalid,
            "D1 target identity was not exact canonical input",
        ));
    }
    Ok(())
}

fn validate_plan(
    target: &D1TargetIdentity,
    plan: &D1ExecuteWritePlan,
    execute_plan_sha256: &str,
    classified_form: D1WriteOperationForm,
) -> Result<(), D1ExactPlanCompositionError> {
    if !valid_sha256(execute_plan_sha256)
        || !valid_sha256(&plan.execution_session_sha256)
        || !valid_sha256(&plan.sql_sha256)
        || !valid_sha256(&plan.params_sha256)
    {
        return Err(composition_error(
            D1ExactPlanCompositionClassification::PlanDigestInvalid,
            "exact write plan contained a malformed digest",
        ));
    }
    if plan.version != REQUIRED_EXECUTE_PLAN_VERSION
        || plan.operation != D1_EXECUTE_WRITE_OPERATION
        || plan.sql_size_bytes == 0
        || plan.params_size_bytes == 0
        || !(1..=MAX_WRITE_ROWS).contains(&plan.max_rows)
        || hash_serialized(plan) != execute_plan_sha256
    {
        return Err(composition_error(
            D1ExactPlanCompositionClassification::PlanProductMismatch,
            "exact write plan contradicted its closed product contract",
        ));
    }
    if plan.account_id != target.account_id
        || plan.database_id != target.database_id
        || plan.target_key_sha256 != target.target_key_sha256()
    {
        return Err(composition_error(
            D1ExactPlanCompositionClassification::PlanTargetMismatch,
            "exact write plan target did not match the verified target",
        ));
    }
    if !statement_kind_matches_form(plan.statement_kind, classified_form) {
        return Err(composition_error(
            D1ExactPlanCompositionClassification::PlanFormMismatch,
            "classified write form contradicted the exact plan statement kind",
        ));
    }
    Ok(())
}

fn validate_relation(value: &str) -> Result<String, D1ExactPlanCompositionError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_RELATION_IDENTITY_BYTES
        || !bytes.iter().all(|byte| matches!(*byte, 0x20..=0x7e))
        || value.to_ascii_lowercase() != value
    {
        return Err(composition_error(
            D1ExactPlanCompositionClassification::ClassifiedRelationInvalid,
            "classified relation was not exact canonical bounded ASCII identity",
        ));
    }
    Ok(value.to_string())
}

fn validate_catalog_receipt(
    target: &D1TargetIdentity,
    receipt: &D1CatalogEvidenceReceipt,
) -> Result<(), D1ExactPlanCompositionError> {
    if receipt.version != REQUIRED_CATALOG_VERSION
        || receipt.operation != D1_CATALOG_EVIDENCE_OPERATION
        || receipt.projection_version != REQUIRED_CATALOG_VERSION
    {
        return Err(composition_error(
            D1ExactPlanCompositionClassification::CatalogProjectionUnsupported,
            "catalog product was outside the required verified projection version",
        ));
    }
    if receipt.target_key_sha256 != target.target_key_sha256()
        || !catalog_receipt_shape_is_consistent(receipt)
    {
        return Err(composition_error(
            D1ExactPlanCompositionClassification::CatalogProductMismatch,
            "verified catalog receipt contradicted the target or aggregate product",
        ));
    }
    Ok(())
}

fn catalog_receipt_shape_is_consistent(receipt: &D1CatalogEvidenceReceipt) -> bool {
    let fact_count = receipt
        .relation_fact_count
        .checked_add(receipt.trigger_owner_fact_count)
        .and_then(|value| value.checked_add(receipt.schema_auxiliary_fact_count))
        .and_then(|value| value.checked_add(receipt.schema_blocker_fact_count))
        .and_then(|value| value.checked_add(receipt.foreign_key_fact_count))
        .and_then(|value| value.checked_add(receipt.foreign_key_blocker_fact_count));
    fact_count == Some(receipt.catalog_row_count)
        && receipt.stable_primary_observations == 2
        && valid_sha256(&receipt.target_key_sha256)
        && valid_sha256(&receipt.query_plan_sha256)
        && valid_sha256(&receipt.query_sha256)
        && valid_sha256(&receipt.catalog_snapshot_sha256)
        && valid_sha256(&receipt.observation_pair_sha256)
}

fn hash_stable_catalog_authority(receipt: &D1CatalogEvidenceReceipt) -> String {
    hash_serialized(&D1StableCatalogAuthorityReceipt {
        version: receipt.version,
        operation: receipt.operation,
        target_key_sha256: &receipt.target_key_sha256,
        query_plan_sha256: &receipt.query_plan_sha256,
        query_sha256: &receipt.query_sha256,
        projection_version: receipt.projection_version,
        catalog_snapshot_sha256: &receipt.catalog_snapshot_sha256,
        catalog_row_count: receipt.catalog_row_count,
        schema_physical_row_count: receipt.schema_physical_row_count,
        relation_fact_count: receipt.relation_fact_count,
        trigger_owner_fact_count: receipt.trigger_owner_fact_count,
        schema_auxiliary_fact_count: receipt.schema_auxiliary_fact_count,
        schema_blocker_fact_count: receipt.schema_blocker_fact_count,
        foreign_key_fact_count: receipt.foreign_key_fact_count,
        foreign_key_blocker_fact_count: receipt.foreign_key_blocker_fact_count,
        conservative_blocker_count: receipt.conservative_blocker_count,
        stable_primary_observations: receipt.stable_primary_observations,
        provider_row_cap: receipt.provider_row_cap,
        provider_byte_cap: receipt.provider_byte_cap,
        response_body_sizes: receipt.response_body_sizes,
    })
}

fn validate_graph_receipt(
    catalog: &D1CatalogEvidenceReceipt,
    graph: &D1ReservedRelationGraphReceipt,
) -> Result<(), D1ExactPlanCompositionError> {
    if graph.version != REQUIRED_GRAPH_VERSION
        || graph.operation != D1_RESERVED_RELATION_GRAPH_OPERATION
        || graph.catalog_projection_version != REQUIRED_CATALOG_VERSION
    {
        return Err(composition_error(
            D1ExactPlanCompositionClassification::GraphProjectionUnsupported,
            "reserved-relation graph was outside the required product version",
        ));
    }
    let decision_count = graph
        .allow_count
        .checked_add(graph.deny_reserved_reachable_count)
        .and_then(|value| value.checked_add(graph.deny_trigger_effects_unproven_count))
        .and_then(|value| value.checked_add(graph.deny_view_write_semantics_unproven_count));
    let relation_count = graph.table_count.checked_add(graph.view_count);
    let root_count = graph
        .configured_reserved_root_count
        .checked_add(graph.automatic_reserved_root_count);
    let node_count = graph.relation_count.checked_mul(3);
    if graph.target_key_sha256 != catalog.target_key_sha256
        || graph.catalog_snapshot_sha256 != catalog.catalog_snapshot_sha256
        || graph.catalog_projection_version != catalog.projection_version
        || graph.catalog_row_count != catalog.catalog_row_count
        || graph.relation_count != catalog.relation_fact_count
        || graph.trigger_fact_count != catalog.trigger_owner_fact_count
        || graph.schema_auxiliary_fact_count != catalog.schema_auxiliary_fact_count
        || graph.foreign_key_fact_count != catalog.foreign_key_fact_count
        || graph.foreign_key_group_count > graph.foreign_key_fact_count
        || graph.trigger_owned_relation_count > graph.trigger_fact_count
        || relation_count != Some(graph.relation_count)
        || root_count != Some(graph.total_reserved_root_count)
        || node_count != Some(graph.graph_node_count)
        || decision_count != Some(graph.graph_node_count)
        || graph.total_reserved_root_count == 0
        || !valid_sha256(&graph.target_key_sha256)
        || !valid_sha256(&graph.catalog_snapshot_sha256)
        || !valid_sha256(&graph.reserved_root_set_sha256)
        || !valid_sha256(&graph.graph_sha256)
        || !valid_sha256(&graph.decision_sha256)
    {
        return Err(composition_error(
            D1ExactPlanCompositionClassification::GraphProductMismatch,
            "reserved-relation graph contradicted the catalog or aggregate product",
        ));
    }
    Ok(())
}

fn validate_primitive_expansion(
    form: D1WriteOperationForm,
    primitives: &[D1RelationWriteOperation],
) -> Result<(), D1ExactPlanCompositionError> {
    let expected = required_relation_write_operations(form).map_err(|_| {
        composition_error(
            D1ExactPlanCompositionClassification::CompoundWriteUnsupported,
            "classified write form is outside the closed primitive expansion contract",
        )
    })?;
    if primitives != expected {
        return Err(composition_error(
            D1ExactPlanCompositionClassification::PrimitiveExpansionMismatch,
            "effective primitives contradicted the closed operation-form expansion",
        ));
    }
    Ok(())
}

fn statement_kind_matches_form(kind: D1WriteStatementKind, form: D1WriteOperationForm) -> bool {
    matches!(
        (kind, form),
        (D1WriteStatementKind::Insert, D1WriteOperationForm::Insert)
            | (
                D1WriteStatementKind::Insert,
                D1WriteOperationForm::InsertOrReplace
            )
            | (
                D1WriteStatementKind::Insert,
                D1WriteOperationForm::UpsertDoUpdate
            )
            | (D1WriteStatementKind::Update, D1WriteOperationForm::Update)
            | (
                D1WriteStatementKind::Update,
                D1WriteOperationForm::UpdateOrReplace
            )
            | (D1WriteStatementKind::Delete, D1WriteOperationForm::Delete)
            | (D1WriteStatementKind::Replace, D1WriteOperationForm::Replace)
    )
}

fn form_label(form: D1WriteOperationForm) -> &'static str {
    match form {
        D1WriteOperationForm::Insert => "insert",
        D1WriteOperationForm::Update => "update",
        D1WriteOperationForm::Delete => "delete",
        D1WriteOperationForm::Replace => "replace",
        D1WriteOperationForm::InsertOrReplace => "insert_or_replace",
        D1WriteOperationForm::UpsertDoUpdate => "upsert_do_update",
        D1WriteOperationForm::UpdateOrReplace => "update_or_replace",
        D1WriteOperationForm::UnsupportedCompound => "unsupported_compound",
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn composition_error(
    classification: D1ExactPlanCompositionClassification,
    message: &'static str,
) -> D1ExactPlanCompositionError {
    D1ExactPlanCompositionError {
        code: "d1.exact_plan_composition_unproven",
        classification,
        message,
    }
}

fn hash_serialized<T: Serialize + ?Sized>(value: &T) -> String {
    let bytes =
        serde_json::to_vec(value).expect("composition evidence serialization is infallible");
    hash_bytes(&bytes)
}

fn hash_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests;
