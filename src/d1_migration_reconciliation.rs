//! Read-only, fail-closed reconciliation for retained D1 migration manifests.
//!
//! The MCP boundary supplies exact manifest bytes and bounded expected states.
//! This module owns validation, fixed-query construction, two-read canonical
//! evidence comparison, convergence classification, and a future-transition
//! plan digest. It never submits caller SQL and never mutates provider or local
//! custody state.

use std::collections::{BTreeMap, BTreeSet};

use rmcp::model::CallToolResult;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::cloudflare::client::{
    D1MigrationReconciliationBatch, D1MigrationReconciliationBatchError,
    D1MigrationReconciliationReadLifecycle,
};
use crate::d1_migration_additive::{
    AddColumnEffect, AdditiveContractError, AdditiveManifestPlan, AdditivePrefixPlan,
    AdditiveStatement, EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1, classify_additive_statement,
    validate_additive_transitions,
};
use crate::d1_migration_lease::{
    D1RetainedMigrationLease, D1RetainedMigrationLeaseIdentity, inspect_retained_d1_migration_lease,
};
use crate::d1_migration_manifest::{
    D1ManifestLedgerRow, classify_d1_manifest_ledger, d1_ledger_summaries, d1_manifest_plan_sha256,
    d1_manifest_summaries,
};
use crate::server::CloudflareMcp;
use crate::tools::{D1MigrationManifestEntry, sha256_bytes_hex};

const OPERATION: &str = "d1_reconcile_migration_manifest";

pub(crate) fn contextualize_d1_reconciliation_semantic_error(
    result: CallToolResult,
) -> CallToolResult {
    let error = result
        .structured_content
        .as_ref()
        .and_then(|content| content.get("error"))
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "code": "d1.migration_reconciliation_invalid_request",
                "message": "migration reconciliation request validation failed closed",
                "hint": "Correct the bounded request fields before another reconciliation attempt.",
            })
        });
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": OPERATION,
        "dry_run": true,
        "read_only": true,
        "status": "reconciliation_required",
        "outcome": "unknown",
        "capability_state": "contradictory",
        "retry_decision": "do_not_retry_same_attempt",
        "lease_decision": "not_acquired",
        "lease_retained": null,
        "custody_status": "not_inspected",
        "query_sha256": null,
        "response_evidence": [],
        "provider_calls": 0,
        "provider_read_lifecycle": [],
        "provider_mutations": 0,
        "local_namespace_mutations": 0,
        "error": error,
    }))
}
pub(crate) const EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1: &str = "schema_create_only_v1";
pub(crate) const EFFECT_ASSERTION_SCHEMA_CREATE_OBJECTS_V1: &str =
    "schema_create_tables_indexes_views_triggers_v1";
const MAX_STATE_EXPECTATIONS: usize = 128;
const MAX_SCHEMA_OBJECTS: usize = 128;
const MAX_TABLES: usize = 64;
const MAX_COLUMNS_PER_TABLE: usize = 256;
const MAX_FOREIGN_KEYS_PER_TABLE: usize = 256;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1ReconcileMigrationManifestArgs {
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
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct D1MigrationStateExpectation {
    pub manifest_prefix_length: usize,
    pub schema_objects: Vec<D1MigrationSchemaObjectExpectation>,
    pub tables: Vec<D1MigrationTableExpectation>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct D1MigrationSchemaObjectExpectation {
    pub object_type: String,
    pub name: String,
    pub table_name: String,
    pub sql_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct D1MigrationTableExpectation {
    pub name: String,
    pub columns: Vec<D1MigrationColumnExpectation>,
    pub foreign_keys: Vec<D1MigrationForeignKeyExpectation>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct D1MigrationColumnExpectation {
    pub cid: i64,
    pub name: String,
    pub declared_type: String,
    pub not_null: bool,
    #[serde(default)]
    pub default_value: Option<String>,
    pub primary_key_position: i64,
    pub hidden: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct D1MigrationForeignKeyExpectation {
    pub id: i64,
    pub sequence: i64,
    pub referenced_table: String,
    pub from_column: String,
    #[serde(default)]
    pub to_column: Option<String>,
    pub on_update: String,
    pub on_delete: String,
    pub match_mode: String,
}

#[derive(Debug)]
struct ValidatedExpectations {
    states: Vec<D1MigrationStateExpectation>,
    object_names: Vec<String>,
    table_names: Vec<String>,
    proof_sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct DerivedSchemaObject {
    object_type: String,
    name: String,
    table_name: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct CanonicalSnapshot {
    ledger: Vec<D1ManifestLedgerRow>,
    schema_objects: Vec<ObservedSchemaObject>,
    tables: Vec<ObservedTable>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ObservedSchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql_sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ObservedTable {
    name: String,
    columns: Vec<D1MigrationColumnExpectation>,
    foreign_keys: Vec<D1MigrationForeignKeyExpectation>,
}

#[derive(Debug, Clone)]
enum BatchStatement {
    Ledger,
    Schema,
    TableXinfo(String),
    ForeignKeyList(String),
    ForeignKeyCheck(String),
}

impl BatchStatement {
    fn marker(&self, proof_sha256: &str) -> String {
        let logical_identity = match self {
            Self::Ledger => "ledger".to_string(),
            Self::Schema => "sqlite_master".to_string(),
            Self::TableXinfo(table) => format!("table_xinfo\0{table}"),
            Self::ForeignKeyList(table) => format!("foreign_key_list\0{table}"),
            Self::ForeignKeyCheck(table) => format!("foreign_key_check\0{table}"),
        };
        sha256_bytes_hex(
            format!("d1-reconciliation-statement-v1\0{proof_sha256}\0{logical_identity}")
                .as_bytes(),
        )
    }

    fn data_fields(&self) -> &'static [&'static str] {
        match self {
            Self::Ledger => &["id", "name"],
            Self::Schema => &["type", "name", "tbl_name", "sql"],
            Self::TableXinfo(_) => &[
                "cid",
                "name",
                "type",
                "notnull",
                "dflt_value",
                "pk",
                "hidden",
            ],
            Self::ForeignKeyList(_) => &[
                "id",
                "seq",
                "table",
                "from",
                "to",
                "on_update",
                "on_delete",
                "match",
            ],
            Self::ForeignKeyCheck(_) => &["table", "rowid", "parent", "fkid"],
        }
    }
}

#[derive(Debug)]
struct FixedQuery {
    sql: String,
    sha256: String,
    proof_sha256: String,
    statements: Vec<BatchStatement>,
}

#[derive(Debug)]
pub(crate) struct D1MigrationReconciliationProof {
    pub(crate) lease: D1RetainedMigrationLease,
    query: FixedQuery,
    first: ParsedBatch,
    second: ParsedBatch,
    pub(crate) expectation_proof_sha256: String,
    pub(crate) canonical_snapshot_sha256: String,
    pub(crate) reconciliation_plan_sha256: String,
    pub(crate) effect_assertion_id: String,
    pub(crate) original_prefix_length: usize,
    pub(crate) current_prefix_length: usize,
    pub(crate) outcome: String,
}

impl D1MigrationReconciliationProof {
    pub(crate) fn query_sha256(&self) -> &str {
        &self.query.sha256
    }

    pub(crate) fn response_evidence(&self) -> Vec<Value> {
        vec![
            response_digest_summary(&self.first),
            response_digest_summary(&self.second),
        ]
    }

    pub(crate) fn provider_read_lifecycle(&self) -> Vec<Value> {
        vec![json!(self.first.lifecycle), json!(self.second.lifecycle)]
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_sha256_for_namespace(
        &self,
        account_id: &str,
        database_id: &str,
        family: &str,
        migrations_table: &str,
        manifest: &[D1MigrationManifestEntry],
        namespace: &str,
    ) -> String {
        let mut identity = self.lease.identity.clone();
        identity.namespace = namespace.to_string();
        reconciliation_plan_sha256(
            account_id,
            database_id,
            family,
            migrations_table,
            manifest,
            &identity,
            self.original_prefix_length,
            self.current_prefix_length,
            &self.outcome,
            &self.query.sha256,
            &self.canonical_snapshot_sha256,
            &self.effect_assertion_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn legacy_plan_sha256_for_namespace(
        &self,
        account_id: &str,
        database_id: &str,
        family: &str,
        migrations_table: &str,
        manifest: &[D1MigrationManifestEntry],
        namespace: &str,
    ) -> String {
        let mut identity = self.lease.identity.clone();
        identity.namespace = namespace.to_string();
        reconciliation_plan_sha256_v1(
            account_id,
            database_id,
            family,
            migrations_table,
            manifest,
            &identity,
            self.original_prefix_length,
            self.current_prefix_length,
            &self.outcome,
            &self.query.sha256,
            &self.canonical_snapshot_sha256,
        )
    }

    pub(crate) fn effect_assertion_scope(&self) -> &'static [&'static str] {
        effect_assertion_scope(&self.effect_assertion_id)
    }

    pub(crate) fn effect_assertion_statement_class(&self) -> &'static str {
        effect_assertion_statement_class(&self.effect_assertion_id)
    }
}

pub(crate) async fn prepare_d1_migration_reconciliation(
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
) -> Result<D1MigrationReconciliationProof, CallToolResult> {
    let selected_effect_assertion_id = match canonical_effect_assertion_id(effect_assertion_id) {
        Ok(id) => id,
        Err(result) => return Err(prelease_error(result, "not_inspected", None)),
    };
    let derived =
        match derive_effect_assertion_details(Some(selected_effect_assertion_id), manifest) {
            Ok(derived) => derived,
            Err(result) => return Err(prelease_error(result, "not_inspected", None)),
        };
    if let Err(result) = validate_reserved_migrations_table(migrations_table, &derived) {
        return Err(prelease_error(result, "not_inspected", None));
    }
    let validated = match validate_expectations(&derived.states, state_expectations) {
        Ok(validated) => validated,
        Err(result) => return Err(prelease_error(result, "not_inspected", None)),
    };
    if let Some(plan) = derived.additive_plan.as_ref() {
        if let Err(error) = validate_additive_transitions(plan, &validated.states) {
            return Err(prelease_error(
                additive_contract_error(error),
                "not_inspected",
                None,
            ));
        }
    }
    let query = build_fixed_query(
        migrations_table,
        manifest.len(),
        &validated.object_names,
        &validated.table_names,
        &validated.proof_sha256,
    );
    let lease = match inspect_retained_d1_migration_lease(
        account_id,
        database_id,
        family,
        approved_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
    ) {
        Ok(lease) => lease,
        Err(result) => {
            return Err(prelease_error(
                result,
                "inspection_failed",
                Some(&query.sha256),
            ));
        }
    };

    let first = match read_complete_batch(server, &lease, account_id, database_id, &query, manifest)
        .await
    {
        Ok(batch) => batch,
        Err(result) => return Err(result),
    };
    let first_digest = batch_digest(&first);
    let second = match read_complete_batch(
        server,
        &lease,
        account_id,
        database_id,
        &query,
        manifest,
    )
    .await
    {
        Ok(batch) => batch,
        Err(result) => {
            return Err(contextualize_error(
                result,
                Some(&query.sha256),
                &[response_digest_summary(&first)],
                1,
            ));
        }
    };
    if let Err(result) = lease.revalidate() {
        return Err(contextualize_unverified_custody_error(
            result,
            Some(&query.sha256),
            &[
                response_digest_summary(&first),
                response_digest_summary(&second),
            ],
            2,
        ));
    }
    let second_digest = batch_digest(&second);
    if first.snapshot != second.snapshot || first_digest != second_digest {
        return Err(contextualize_error(
            reconciliation_error_with_evidence(
                "contradictory",
                "d1.migration_reconciliation_evidence_unstable",
                "two complete read-only reconciliation batches were not canonically equivalent",
                Some(&query.sha256),
                &[
                    response_digest_summary(&first),
                    response_digest_summary(&second),
                ],
            ),
            Some(&query.sha256),
            &[],
            2,
        ));
    }

    let ledger_classification = match classify_d1_manifest_ledger(manifest, &first.snapshot.ledger)
    {
        Ok(classification) => classification,
        Err(_) => {
            return Err(contextualize_error(
                reconciliation_error_with_evidence(
                    "contradictory",
                    "d1.migration_reconciliation_ledger_not_manifest_prefix",
                    "stable migration ledger is not an exact prefix of the supplied manifest",
                    Some(&query.sha256),
                    &[
                        response_digest_summary(&first),
                        response_digest_summary(&second),
                    ],
                ),
                Some(&query.sha256),
                &[],
                2,
            ));
        }
    };
    let original_prefix = match reconstruct_unique_original_prefix(
        account_id,
        database_id,
        family,
        migrations_table,
        manifest,
        &first.snapshot.ledger,
        approved_plan_sha256,
    ) {
        Ok(prefix) => prefix,
        Err(result) => {
            return Err(contextualize_error(
                result,
                Some(&query.sha256),
                &[
                    response_digest_summary(&first),
                    response_digest_summary(&second),
                ],
                2,
            ));
        }
    };
    let current_prefix = ledger_classification.applied_names.len();
    let expected_state = match validated
        .states
        .iter()
        .find(|state| state.manifest_prefix_length == current_prefix)
    {
        Some(state) => state,
        None => {
            return Err(contextualize_error(
                reconciliation_error_with_evidence(
                    "capability_gap",
                    "d1.migration_reconciliation_state_expectation_missing",
                    "no bounded reviewed state expectation covers the stable current manifest prefix",
                    Some(&query.sha256),
                    &[
                        response_digest_summary(&first),
                        response_digest_summary(&second),
                    ],
                ),
                Some(&query.sha256),
                &[],
                2,
            ));
        }
    };
    if let Err(result) = verify_expected_state(expected_state, &validated, &first.snapshot) {
        return Err(contextualize_error(
            result,
            Some(&query.sha256),
            &[
                response_digest_summary(&first),
                response_digest_summary(&second),
            ],
            2,
        ));
    }

    let outcome = if current_prefix == original_prefix {
        "not_committed"
    } else if current_prefix == manifest.len() {
        "full_state_converged"
    } else if current_prefix > original_prefix {
        "partial_state_converged"
    } else {
        "unknown"
    };
    if outcome == "unknown" {
        return Err(contextualize_error(
            reconciliation_error_with_evidence(
                "contradictory",
                "d1.migration_reconciliation_plan_relationship_contradictory",
                "stable ledger precedes the uniquely reconstructed approved-plan prefix",
                Some(&query.sha256),
                &[
                    response_digest_summary(&first),
                    response_digest_summary(&second),
                ],
            ),
            Some(&query.sha256),
            &[],
            2,
        ));
    }

    let snapshot_sha256 = first_digest;
    let reconciliation_plan_sha256 = reconciliation_plan_sha256(
        account_id,
        database_id,
        family,
        migrations_table,
        manifest,
        &lease.identity,
        original_prefix,
        current_prefix,
        outcome,
        &query.sha256,
        &snapshot_sha256,
        selected_effect_assertion_id,
    );
    Ok(D1MigrationReconciliationProof {
        lease,
        query,
        first,
        second,
        expectation_proof_sha256: validated.proof_sha256,
        canonical_snapshot_sha256: snapshot_sha256,
        reconciliation_plan_sha256,
        effect_assertion_id: selected_effect_assertion_id.to_string(),
        original_prefix_length: original_prefix,
        current_prefix_length: current_prefix,
        outcome: outcome.to_string(),
    })
}

pub(crate) async fn reconcile_d1_migration_manifest(
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
) -> CallToolResult {
    let proof = match prepare_d1_migration_reconciliation(
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
        Err(result) => return result,
    };
    CallToolResult::structured(json!({
        "ok": true,
        "operation": OPERATION,
        "dry_run": true,
        "read_only": true,
        "status": "reconciliation_evidence_ready",
        "outcome": proof.outcome,
        "retry_decision": "do_not_retry_same_attempt",
        "lease_decision": "retain",
        "lease_retained": true,
        "custody_status": "retained_evidence_verified",
        "provider_attempt_causality": "not_claimed",
        "inference_basis": "documented_atomic_state_inference_from_stable_ledger_schema_and_foreign_key_evidence",
        "account_id": account_id,
        "database_id": database_id,
        "migration_family": family,
        "migrations_table": migrations_table,
        "manifest": d1_manifest_summaries(manifest),
        "approved_plan_sha256": approved_plan_sha256,
        "reconstructed_original_prefix_length": proof.original_prefix_length,
        "current_manifest_prefix_length": proof.current_prefix_length,
        "ledger": d1_ledger_summaries(&proof.first.snapshot.ledger),
        "lease": proof.lease.identity,
        "query_sha256": proof.query.sha256,
        "expectation_proof_sha256": proof.expectation_proof_sha256,
        "query_sha256s": [&proof.query.sha256, &proof.query.sha256],
        "response_evidence": [response_digest_summary(&proof.first), response_digest_summary(&proof.second)],
        "provider_read_lifecycle": [proof.first.lifecycle, proof.second.lifecycle],
        "canonical_snapshot_sha256": proof.canonical_snapshot_sha256,
        "scope_completeness": {
            "ledger": "complete_bounded_manifest_prefix",
            "sqlite_master": "complete_exact_declared_object_union",
            "table_xinfo": "complete_exact_declared_table_union",
            "foreign_key_list": "complete_exact_declared_table_union",
            "foreign_key_check": "bounded_zero_violation_proof_for_every_declared_table",
            "migration_effects": proof.effect_assertion_id,
        },
        "effect_assertion": {
            "id": proof.effect_assertion_id,
            "scope": {
                "statement_class": proof.effect_assertion_statement_class(),
                "schema_object_types": proof.effect_assertion_scope(),
            },
            "source": "built_in_registry_and_exact_manifest_sql_classification",
            "caller_schema_only_declaration_used": false,
        },
        "reconciliation_plan_sha256": proof.reconciliation_plan_sha256,
        "future_live_transition": "use_d1_finalize_migration_reconciliation_after_independent_approval",
        "provider_calls": 2,
        "provider_mutations": 0,
        "local_namespace_mutations": 0,
    }))
}

#[derive(Debug, Clone)]
pub(crate) struct D1MigrationReconciliationRefresh {
    pub(crate) response_evidence: Value,
    pub(crate) lifecycle: Value,
}

pub(crate) async fn refresh_d1_migration_reconciliation(
    server: &CloudflareMcp,
    proof: &D1MigrationReconciliationProof,
    account_id: &str,
    database_id: &str,
    manifest: &[D1MigrationManifestEntry],
) -> Result<D1MigrationReconciliationRefresh, CallToolResult> {
    let batch = read_complete_batch(
        server,
        &proof.lease,
        account_id,
        database_id,
        &proof.query,
        manifest,
    )
    .await?;
    proof.lease.revalidate().map_err(|result| {
        contextualize_unverified_custody_error(
            result,
            Some(&proof.query.sha256),
            &[response_digest_summary(&batch)],
            1,
        )
    })?;
    if batch.snapshot != proof.first.snapshot
        || batch_digest(&batch) != proof.canonical_snapshot_sha256
    {
        return Err(contextualize_error(
            reconciliation_error_with_evidence(
                "contradictory",
                "d1.migration_reconciliation_fresh_state_changed",
                "fresh primary-current evidence no longer matches the approved canonical snapshot",
                Some(&proof.query.sha256),
                &[response_digest_summary(&batch)],
            ),
            Some(&proof.query.sha256),
            &[],
            1,
        ));
    }
    Ok(D1MigrationReconciliationRefresh {
        response_evidence: response_digest_summary(&batch),
        lifecycle: json!(batch.lifecycle),
    })
}

#[derive(Debug)]
struct ParsedBatch {
    snapshot: CanonicalSnapshot,
    response_body_sha256: String,
    response_body_size_bytes: usize,
    lifecycle: D1MigrationReconciliationReadLifecycle,
}

async fn read_complete_batch(
    server: &CloudflareMcp,
    lease: &D1RetainedMigrationLease,
    account_id: &str,
    database_id: &str,
    query: &FixedQuery,
    manifest: &[D1MigrationManifestEntry],
) -> Result<ParsedBatch, CallToolResult> {
    lease.revalidate().map_err(|result| {
        contextualize_unverified_custody_error(result, Some(&query.sha256), &[], 0)
    })?;
    let batch = match server
        .cloudflare
        .query_d1_migration_reconciliation_batch(account_id, database_id, &query.sql)
        .await
    {
        Ok(batch) => batch,
        Err(error) => {
            let provider_calls = error.lifecycle.provider_calls();
            let provider_error = adapter_batch_error(error, &query.sha256);
            return Err(match lease.revalidate() {
                Ok(()) => contextualize_error(provider_error, Some(&query.sha256), &[], 0),
                Err(custody_error) => contextualize_provider_error_with_unverified_custody(
                    provider_error,
                    custody_error,
                    Some(&query.sha256),
                    provider_calls,
                ),
            });
        }
    };
    lease.revalidate().map_err(|result| {
        contextualize_unverified_custody_error(
            result,
            Some(&query.sha256),
            &[response_digest_summary_from_adapter(&batch)],
            1,
        )
    })?;
    let snapshot = parse_complete_batch(
        &batch.result,
        &query.statements,
        &query.proof_sha256,
        manifest,
    )
    .map_err(|result| {
        contextualize_error(
            result,
            Some(&query.sha256),
            &[response_digest_summary_from_adapter(&batch)],
            1,
        )
    })?;
    Ok(ParsedBatch {
        snapshot,
        response_body_sha256: batch.response_body_sha256,
        response_body_size_bytes: batch.response_body_size_bytes,
        lifecycle: batch.lifecycle,
    })
}

fn validate_expectations(
    derived_states: &[Vec<DerivedSchemaObject>],
    states: Vec<D1MigrationStateExpectation>,
) -> Result<ValidatedExpectations, CallToolResult> {
    let manifest_len = derived_states.len().saturating_sub(1);
    if states.len() != derived_states.len() || states.len() > MAX_STATE_EXPECTATIONS {
        return Err(reconciliation_error(
            "capability_gap",
            "d1.migration_reconciliation_expectations_incomplete",
            "state_expectations must contain one complete reviewed state for every manifest prefix, including zero",
        ));
    }
    let mut previous_prefix = None;
    let mut object_names = BTreeSet::new();
    let mut table_names = BTreeSet::new();
    for (expected_prefix, state) in states.iter().enumerate() {
        if state.manifest_prefix_length != expected_prefix
            || state.manifest_prefix_length > manifest_len
            || previous_prefix.is_some_and(|prefix| prefix >= state.manifest_prefix_length)
        {
            return Err(reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_expectations_noncanonical",
                "state expectations must be unique and strictly ordered by an in-range manifest prefix",
            ));
        }
        previous_prefix = Some(state.manifest_prefix_length);
        if state.schema_objects.len() > MAX_SCHEMA_OBJECTS || state.tables.len() > MAX_TABLES {
            return Err(reconciliation_error(
                "capability_gap",
                "d1.migration_reconciliation_expectations_unbounded",
                "a state expectation exceeds the schema object or table proof bound",
            ));
        }
        let mut previous_object = None::<(String, String)>;
        let mut state_table_objects = BTreeSet::new();
        let mut supplied_derived_objects = Vec::new();
        for object in &state.schema_objects {
            validate_identifier("schema object name", &object.name)?;
            validate_identifier("schema object table_name", &object.table_name)?;
            if !matches!(
                object.object_type.as_str(),
                "table" | "index" | "view" | "trigger"
            ) || !valid_sha256(&object.sql_sha256)
            {
                return Err(reconciliation_error(
                    "capability_gap",
                    "d1.migration_reconciliation_schema_expectation_invalid",
                    "schema objects must be table/index/view/trigger entries with lowercase exact SQL SHA-256 digests",
                ));
            }
            let key = (object.object_type.clone(), object.name.clone());
            if previous_object
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            {
                return Err(reconciliation_error(
                    "contradictory",
                    "d1.migration_reconciliation_expectations_noncanonical",
                    "schema object expectations must be unique and strictly ordered by type then name",
                ));
            }
            previous_object = Some(key);
            if object.object_type == "table" {
                if object.name != object.table_name {
                    return Err(reconciliation_error(
                        "contradictory",
                        "d1.migration_reconciliation_schema_expectation_invalid",
                        "a table schema object must bind its own exact table name",
                    ));
                }
                state_table_objects.insert(object.name.clone());
            } else if object.object_type == "view" && object.name != object.table_name {
                return Err(reconciliation_error(
                    "contradictory",
                    "d1.migration_reconciliation_schema_expectation_invalid",
                    "a view schema object must bind its own exact sqlite_master table name",
                ));
            }
            supplied_derived_objects.push(DerivedSchemaObject {
                object_type: object.object_type.clone(),
                name: object.name.clone(),
                table_name: object.table_name.clone(),
            });
            object_names.insert(object.name.clone());
        }
        if supplied_derived_objects != derived_states[expected_prefix] {
            return Err(reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_schema_expectation_incomplete",
                "schema object expectations must exactly match every CREATE target derived from the manifest prefix",
            ));
        }
        let mut previous_table = None::<String>;
        for table in &state.tables {
            validate_identifier("table expectation name", &table.name)?;
            if previous_table
                .as_ref()
                .is_some_and(|previous| previous >= &table.name)
            {
                return Err(reconciliation_error(
                    "contradictory",
                    "d1.migration_reconciliation_expectations_noncanonical",
                    "table expectations must be unique and strictly ordered by name",
                ));
            }
            previous_table = Some(table.name.clone());
            if !state_table_objects.remove(&table.name)
                || table.columns.is_empty()
                || table.columns.len() > MAX_COLUMNS_PER_TABLE
                || table.foreign_keys.len() > MAX_FOREIGN_KEYS_PER_TABLE
            {
                return Err(reconciliation_error(
                    "contradictory",
                    "d1.migration_reconciliation_table_expectation_invalid",
                    "every declared table object needs one bounded non-empty table_xinfo expectation",
                ));
            }
            validate_columns(&table.columns)?;
            validate_foreign_keys(&table.foreign_keys)?;
            table_names.insert(table.name.clone());
        }
        if !state_table_objects.is_empty() {
            return Err(reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_table_expectation_missing",
                "every expected table schema object requires table_xinfo and foreign-key expectations",
            ));
        }
        if state.schema_objects.iter().any(|object| {
            object.object_type == "index"
                && !state
                    .tables
                    .iter()
                    .any(|table| table.name == object.table_name)
        }) {
            return Err(reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_index_parent_missing",
                "every expected index must bind an expected table in the same state",
            ));
        }
        if state.schema_objects.iter().any(|object| {
            object.object_type == "trigger"
                && !state
                    .tables
                    .iter()
                    .any(|table| table.name == object.table_name)
        }) {
            return Err(reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_trigger_parent_missing",
                "every expected trigger must bind an expected table in the same state",
            ));
        }
    }
    if object_names.len() > MAX_SCHEMA_OBJECTS || table_names.len() > MAX_TABLES {
        return Err(reconciliation_error(
            "capability_gap",
            "d1.migration_reconciliation_expectation_union_unbounded",
            "the union of reviewed schema objects or tables exceeds the fixed query bound",
        ));
    }
    let proof_sha256 = sha256_bytes_hex(
        &serde_json::to_vec(&states)
            .expect("validated reconciliation expectations serialize canonically"),
    );
    Ok(ValidatedExpectations {
        states,
        object_names: object_names.into_iter().collect(),
        table_names: table_names.into_iter().collect(),
        proof_sha256,
    })
}

fn validate_columns(columns: &[D1MigrationColumnExpectation]) -> Result<(), CallToolResult> {
    let mut previous_cid = None;
    let mut names = BTreeSet::new();
    for column in columns {
        validate_identifier("column name", &column.name)?;
        if column.cid < 0
            || previous_cid.is_some_and(|cid| cid >= column.cid)
            || !names.insert(column.name.clone())
            || column.primary_key_position < 0
            || !(0..=3).contains(&column.hidden)
            || column.declared_type.len() > 128
            || column.declared_type.contains('\0')
            || column
                .default_value
                .as_ref()
                .is_some_and(|value| value.len() > 1024 || value.contains('\0'))
        {
            return Err(reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_column_expectation_invalid",
                "table_xinfo expectations must be bounded, uniquely ordered, and contain canonical scalar fields",
            ));
        }
        previous_cid = Some(column.cid);
    }
    Ok(())
}

fn validate_foreign_keys(
    foreign_keys: &[D1MigrationForeignKeyExpectation],
) -> Result<(), CallToolResult> {
    let mut previous = None;
    for foreign_key in foreign_keys {
        validate_identifier(
            "foreign key referenced_table",
            &foreign_key.referenced_table,
        )?;
        validate_identifier("foreign key from_column", &foreign_key.from_column)?;
        if let Some(to_column) = foreign_key.to_column.as_deref() {
            validate_identifier("foreign key to_column", to_column)?;
        }
        let key = (foreign_key.id, foreign_key.sequence);
        if foreign_key.id < 0
            || foreign_key.sequence < 0
            || previous.is_some_and(|prior| prior >= key)
            || !valid_foreign_key_action(&foreign_key.on_update)
            || !valid_foreign_key_action(&foreign_key.on_delete)
            || !matches!(
                foreign_key.match_mode.as_str(),
                "NONE" | "SIMPLE" | "PARTIAL" | "FULL"
            )
        {
            return Err(reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_foreign_key_expectation_invalid",
                "foreign-key expectations must be uniquely ordered and use canonical SQLite actions",
            ));
        }
        previous = Some(key);
    }
    Ok(())
}

fn valid_foreign_key_action(value: &str) -> bool {
    matches!(
        value,
        "NO ACTION" | "RESTRICT" | "SET NULL" | "SET DEFAULT" | "CASCADE"
    )
}

fn validate_identifier(label: &str, value: &str) -> Result<(), CallToolResult> {
    let mut bytes = value.bytes();
    let valid = value.len() <= 128
        && matches!(bytes.next(), Some(byte) if byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric());
    if valid {
        Ok(())
    } else {
        let _ = label;
        Err(reconciliation_error(
            "capability_gap",
            "d1.migration_reconciliation_identifier_invalid",
            "a schema, table, column, or foreign-key identifier was not canonical bounded ASCII",
        ))
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SqlToken {
    Word(String),
    Identifier(String),
    StringLiteral(String),
    Symbol(char),
}

#[derive(Debug)]
struct DerivedEffectAssertion {
    states: Vec<Vec<DerivedSchemaObject>>,
    additive_plan: Option<AdditiveManifestPlan>,
}

#[derive(Debug, Clone)]
enum ClassifiedEffect {
    Create(DerivedSchemaObject),
    AddColumn(AddColumnEffect),
    ForeignKeysOn,
}

#[cfg(test)]
fn derive_effect_assertion(
    effect_assertion_id: Option<&str>,
    manifest: &[D1MigrationManifestEntry],
) -> Result<Vec<Vec<DerivedSchemaObject>>, CallToolResult> {
    derive_effect_assertion_details(effect_assertion_id, manifest).map(|derived| derived.states)
}

fn derive_effect_assertion_details(
    effect_assertion_id: Option<&str>,
    manifest: &[D1MigrationManifestEntry],
) -> Result<DerivedEffectAssertion, CallToolResult> {
    let selected = canonical_effect_assertion_id(effect_assertion_id)?;
    let (allow_views_and_triggers, unclassified_message) = match selected {
        EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1 => (
            false,
            "the built-in effect registry cannot exactly prove arbitrary DML, ALTER, DROP, PRAGMA, trigger, view, virtual table, or data-producing CREATE effects",
        ),
        EFFECT_ASSERTION_SCHEMA_CREATE_OBJECTS_V1 => (
            true,
            "the selected effect assertion cannot exactly prove this statement or any arbitrary top-level DML, ALTER, DROP, PRAGMA, virtual table, or data-producing CREATE effect",
        ),
        EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1 => {
            return derive_additive_effect_assertion(manifest);
        }
        _ => unreachable!("canonical registry assertion"),
    };
    let mut cumulative = BTreeMap::<(String, String), DerivedSchemaObject>::new();
    let mut cumulative_names = BTreeSet::new();
    let mut states = vec![Vec::new()];
    for migration in manifest {
        let statements = tokenize_sql_statements(&migration.sql).ok_or_else(|| {
            reconciliation_error(
                "capability_gap",
                "d1.migration_reconciliation_effect_proof_unavailable",
                "exact migration SQL could not be classified by the built-in effect registry",
            )
        })?;
        if statements.is_empty() {
            return Err(reconciliation_error(
                "capability_gap",
                "d1.migration_reconciliation_effect_proof_unavailable",
                "the built-in effect registry cannot exactly prove arbitrary DML, ALTER, DROP, PRAGMA, trigger, view, or data-copy effects",
            ));
        }
        for tokens in statements {
            let object =
                classify_schema_create(&tokens, allow_views_and_triggers).ok_or_else(|| {
                    reconciliation_error(
                        "capability_gap",
                        "d1.migration_reconciliation_effect_proof_unavailable",
                        unclassified_message,
                    )
                })?;
            let key = (object.object_type.clone(), object.name.clone());
            if !cumulative_names.insert(object.name.clone())
                || cumulative.insert(key, object).is_some()
            {
                return Err(reconciliation_error(
                    "contradictory",
                    "d1.migration_reconciliation_create_target_reused",
                    "the manifest reuses a CREATE schema identity and cannot derive one exact schema state per prefix",
                ));
            }
        }
        states.push(cumulative.values().cloned().collect());
    }
    Ok(DerivedEffectAssertion {
        states,
        additive_plan: None,
    })
}

fn derive_additive_effect_assertion(
    manifest: &[D1MigrationManifestEntry],
) -> Result<DerivedEffectAssertion, CallToolResult> {
    let mut migrations = Vec::with_capacity(manifest.len());
    for migration in manifest {
        let statements = tokenize_sql_statements(&migration.sql).ok_or_else(|| {
            reconciliation_error(
                "capability_gap",
                "d1.migration_reconciliation_effect_proof_unavailable",
                "exact migration SQL could not be classified by the additive effect registry",
            )
        })?;
        if statements.is_empty() {
            return Err(reconciliation_error(
                "capability_gap",
                "d1.migration_reconciliation_effect_proof_unavailable",
                "the additive effect registry requires at least one classified statement per manifest entry",
            ));
        }
        let mut effects = Vec::with_capacity(statements.len());
        let mut addition_count = 0usize;
        let mut pragma_count = 0usize;
        for tokens in statements {
            if let Some(object) = classify_schema_create(&tokens, true) {
                effects.push(ClassifiedEffect::Create(object));
                continue;
            }
            match classify_additive_statement(&tokens).map_err(additive_contract_error)? {
                Some(AdditiveStatement::AddColumn(effect)) => {
                    addition_count += 1;
                    effects.push(ClassifiedEffect::AddColumn(effect));
                }
                Some(AdditiveStatement::ForeignKeysOn) => {
                    pragma_count += 1;
                    effects.push(ClassifiedEffect::ForeignKeysOn);
                }
                None => {
                    return Err(reconciliation_error(
                        "capability_gap",
                        "d1.migration_reconciliation_effect_proof_unavailable",
                        "the additive assertion cannot prove this statement or any arbitrary DML, ALTER, DROP, PRAGMA, virtual table, or data-producing CREATE effect",
                    ));
                }
            }
        }
        if addition_count > 1 || pragma_count > 1 {
            return Err(reconciliation_error(
                "capability_gap",
                "d1.migration_reconciliation_additive_prefix_unbounded",
                "each additive manifest prefix may contain at most one ADD COLUMN and one semantic foreign_keys directive",
            ));
        }
        migrations.push(effects);
    }

    let mut created_names = BTreeMap::<String, (String, usize)>::new();
    let mut preexisting_tables = BTreeSet::new();
    for (prefix, effects) in migrations.iter().enumerate() {
        for effect in effects {
            match effect {
                ClassifiedEffect::Create(object) => {
                    if preexisting_tables.contains(&object.name)
                        || created_names
                            .insert(object.name.clone(), (object.object_type.clone(), prefix))
                            .is_some()
                    {
                        return Err(reconciliation_error(
                            "contradictory",
                            "d1.migration_reconciliation_create_target_reused",
                            "the manifest reuses a CREATE or additive parent identity and cannot derive exact prefix states",
                        ));
                    }
                }
                ClassifiedEffect::AddColumn(effect) => {
                    if let Some((object_type, created_prefix)) =
                        created_names.get(&effect.table_name)
                    {
                        if object_type != "table" || *created_prefix >= prefix {
                            return Err(reconciliation_error(
                                "contradictory",
                                "d1.migration_reconciliation_additive_parent_missing",
                                "ADD COLUMN must target a pre-existing table or a table created in an earlier manifest prefix",
                            ));
                        }
                    } else {
                        preexisting_tables.insert(effect.table_name.clone());
                    }
                }
                ClassifiedEffect::ForeignKeysOn => {}
            }
        }
    }

    let mut cumulative = preexisting_tables
        .into_iter()
        .map(|name| {
            (
                ("table".to_string(), name.clone()),
                DerivedSchemaObject {
                    object_type: "table".to_string(),
                    table_name: name.clone(),
                    name,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut states = vec![cumulative.values().cloned().collect()];
    let mut prefixes = Vec::with_capacity(migrations.len());
    for effects in migrations {
        let mut prefix = AdditivePrefixPlan::default();
        for effect in effects {
            match effect {
                ClassifiedEffect::Create(object) => {
                    prefix
                        .created_objects
                        .insert((object.object_type.clone(), object.name.clone()));
                    cumulative.insert((object.object_type.clone(), object.name.clone()), object);
                }
                ClassifiedEffect::AddColumn(effect) => prefix.addition = Some(effect),
                ClassifiedEffect::ForeignKeysOn => prefix.foreign_keys_on = true,
            }
        }
        states.push(cumulative.values().cloned().collect());
        prefixes.push(prefix);
    }
    Ok(DerivedEffectAssertion {
        states,
        additive_plan: Some(AdditiveManifestPlan { prefixes }),
    })
}

fn additive_contract_error(error: AdditiveContractError) -> CallToolResult {
    reconciliation_error(error.capability_state, error.code, error.message)
}

pub(crate) fn canonical_effect_assertion_id(
    effect_assertion_id: Option<&str>,
) -> Result<&'static str, CallToolResult> {
    match effect_assertion_id {
        Some(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1) => Ok(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1),
        Some(EFFECT_ASSERTION_SCHEMA_CREATE_OBJECTS_V1) => {
            Ok(EFFECT_ASSERTION_SCHEMA_CREATE_OBJECTS_V1)
        }
        Some(EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1) => Ok(EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1),
        _ => Err(reconciliation_error(
            "capability_gap",
            "d1.migration_reconciliation_effect_assertion_missing",
            "a supported registry-backed migration effect assertion is required",
        )),
    }
}

pub(crate) fn validate_replay_manifest_expectations(
    effect_assertion_id: &str,
    migrations_table: &str,
    manifest: &[D1MigrationManifestEntry],
    state_expectations: &[D1MigrationStateExpectation],
) -> Result<String, CallToolResult> {
    let selected = canonical_effect_assertion_id(Some(effect_assertion_id))?;
    let derived = derive_effect_assertion_details(Some(selected), manifest)?;
    validate_reserved_migrations_table(migrations_table, &derived)?;
    let validated = validate_expectations(&derived.states, state_expectations.to_vec())?;
    if let Some(plan) = derived.additive_plan.as_ref() {
        validate_additive_transitions(plan, &validated.states).map_err(additive_contract_error)?;
    }
    Ok(validated.proof_sha256)
}

fn validate_reserved_migrations_table(
    migrations_table: &str,
    derived: &DerivedEffectAssertion,
) -> Result<(), CallToolResult> {
    let conflicts = derived.states.last().into_iter().flatten().any(|object| {
        object.name.eq_ignore_ascii_case(migrations_table)
            || object.table_name.eq_ignore_ascii_case(migrations_table)
    });
    if conflicts {
        return Err(reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_migrations_table_reserved",
            "the configured migrations table is reserved and cannot be created, indexed, used as a trigger parent, named as another schema object, or altered by a reconciled manifest",
        ));
    }
    Ok(())
}

fn effect_assertion_scope(effect_assertion_id: &str) -> &'static [&'static str] {
    match effect_assertion_id {
        EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1 => &["table", "index"],
        EFFECT_ASSERTION_SCHEMA_CREATE_OBJECTS_V1 => &["table", "index", "view", "trigger"],
        EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1 => &[
            "table",
            "index",
            "view",
            "trigger",
            "alter_table_add_column",
            "pragma_foreign_keys_on",
        ],
        _ => &[],
    }
}

fn effect_assertion_statement_class(effect_assertion_id: &str) -> &'static str {
    match effect_assertion_id {
        EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1 => "schema_create_only",
        EFFECT_ASSERTION_SCHEMA_CREATE_OBJECTS_V1 => "schema_create_tables_indexes_views_triggers",
        EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1 => "schema_create_objects_additive",
        _ => "unsupported",
    }
}

fn classify_schema_create(
    tokens: &[SqlToken],
    allow_views_and_triggers: bool,
) -> Option<DerivedSchemaObject> {
    if !token_is_word(tokens.first(), "create") {
        return None;
    }
    let mut cursor = 1;
    let unique = if token_is_word(tokens.get(cursor), "unique") {
        cursor += 1;
        true
    } else {
        false
    };
    let object_type = if token_is_word(tokens.get(cursor), "table") && !unique {
        cursor += 1;
        "table"
    } else if token_is_word(tokens.get(cursor), "index") {
        cursor += 1;
        "index"
    } else if allow_views_and_triggers && token_is_word(tokens.get(cursor), "view") && !unique {
        cursor += 1;
        "view"
    } else if allow_views_and_triggers && token_is_word(tokens.get(cursor), "trigger") && !unique {
        cursor += 1;
        "trigger"
    } else {
        return None;
    };
    if token_is_word(tokens.get(cursor), "if")
        && token_is_word(tokens.get(cursor + 1), "not")
        && token_is_word(tokens.get(cursor + 2), "exists")
    {
        cursor += 3;
    }
    let name = token_identifier(tokens.get(cursor))?;
    validate_identifier("derived CREATE object", &name).ok()?;
    cursor += 1;

    if object_type == "table" {
        if tokens.get(cursor) != Some(&SqlToken::Symbol('(')) {
            // This rejects CREATE TABLE AS SELECT, CREATE TABLE AS VALUES, and
            // every other data-producing table form before provider access.
            return None;
        }
        let after_definition = balanced_parenthesized_end(tokens, cursor)?;
        if !valid_table_suffix(&tokens[after_definition..]) {
            return None;
        }
        Some(DerivedSchemaObject {
            object_type: object_type.to_string(),
            table_name: name.clone(),
            name,
        })
    } else if object_type == "index" {
        if !token_is_word(tokens.get(cursor), "on") {
            return None;
        }
        let table_name = token_identifier(tokens.get(cursor + 1))?;
        validate_identifier("derived CREATE INDEX parent", &table_name).ok()?;
        if tokens.get(cursor + 2) != Some(&SqlToken::Symbol('(')) {
            return None;
        }
        let after_columns = balanced_parenthesized_end(tokens, cursor + 2)?;
        if after_columns < tokens.len() && !token_is_word(tokens.get(after_columns), "where") {
            return None;
        }
        Some(DerivedSchemaObject {
            object_type: object_type.to_string(),
            name,
            table_name,
        })
    } else if object_type == "view" {
        if tokens.get(cursor) == Some(&SqlToken::Symbol('(')) {
            cursor = balanced_parenthesized_end(tokens, cursor)?;
        }
        if !token_is_word(tokens.get(cursor), "as")
            || !matches!(
                tokens.get(cursor + 1),
                Some(SqlToken::Word(word))
                    if matches_ignore_ascii_case(word, &["select", "with", "values"])
            )
            || cursor + 2 >= tokens.len()
            || tokens[cursor + 1..]
                .iter()
                .any(|token| token == &SqlToken::Symbol(';'))
        {
            return None;
        }
        Some(DerivedSchemaObject {
            object_type: object_type.to_string(),
            table_name: name.clone(),
            name,
        })
    } else {
        let timing = tokens.get(cursor).and_then(|token| match token {
            SqlToken::Word(word) if word.eq_ignore_ascii_case("before") => Some(1),
            SqlToken::Word(word) if word.eq_ignore_ascii_case("after") => Some(1),
            SqlToken::Word(word) if word.eq_ignore_ascii_case("instead") => {
                token_is_word(tokens.get(cursor + 1), "of").then_some(2)
            }
            _ => None,
        });
        if let Some(width) = timing {
            cursor += width;
        }
        if token_is_word(tokens.get(cursor), "delete")
            || token_is_word(tokens.get(cursor), "insert")
        {
            cursor += 1;
        } else if token_is_word(tokens.get(cursor), "update") {
            cursor += 1;
            if token_is_word(tokens.get(cursor), "of") {
                cursor += 1;
                let mut needs_identifier = true;
                loop {
                    if needs_identifier {
                        let column = token_identifier(tokens.get(cursor))?;
                        validate_identifier("derived CREATE TRIGGER update column", &column)
                            .ok()?;
                        cursor += 1;
                        needs_identifier = false;
                    } else if tokens.get(cursor) == Some(&SqlToken::Symbol(',')) {
                        cursor += 1;
                        needs_identifier = true;
                    } else {
                        break;
                    }
                }
                if needs_identifier {
                    return None;
                }
            }
        } else {
            return None;
        }
        if !token_is_word(tokens.get(cursor), "on") {
            return None;
        }
        let table_name = token_identifier(tokens.get(cursor + 1))?;
        validate_identifier("derived CREATE TRIGGER parent", &table_name).ok()?;
        cursor += 2;
        if tokens.get(cursor) == Some(&SqlToken::Symbol('.')) {
            return None;
        }
        let begin = tokens[cursor..]
            .iter()
            .position(|token| token_is_word(Some(token), "begin"))?
            + cursor;
        let end = tokens.len().checked_sub(1)?;
        let header_suffix = &tokens[cursor..begin];
        let mut header_cursor = 0usize;
        if token_is_word(header_suffix.get(header_cursor), "for")
            && token_is_word(header_suffix.get(header_cursor + 1), "each")
            && token_is_word(header_suffix.get(header_cursor + 2), "row")
        {
            header_cursor += 3;
        }
        if token_is_word(header_suffix.get(header_cursor), "when") {
            header_cursor += 1;
            if header_cursor >= header_suffix.len() {
                return None;
            }
            header_cursor = header_suffix.len();
        }
        let body = tokens.get(begin + 1..end)?;
        if !token_is_word(tokens.get(end), "end")
            || header_cursor != header_suffix.len()
            || header_suffix
                .iter()
                .any(|token| token == &SqlToken::Symbol(';'))
            || !valid_trigger_body(body)
        {
            return None;
        }
        Some(DerivedSchemaObject {
            object_type: object_type.to_string(),
            name,
            table_name,
        })
    }
}

fn valid_trigger_body(tokens: &[SqlToken]) -> bool {
    if tokens.is_empty() || tokens.last() != Some(&SqlToken::Symbol(';')) {
        return false;
    }
    let mut statement_start = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        if token != &SqlToken::Symbol(';') {
            continue;
        }
        if statement_start == index
            || !matches!(
                tokens.get(statement_start),
                Some(SqlToken::Word(word))
                    if matches_ignore_ascii_case(word, &["delete", "insert", "select", "update"])
            )
        {
            return false;
        }
        statement_start = index + 1;
    }
    statement_start == tokens.len()
}

fn matches_ignore_ascii_case(value: &str, allowed: &[&str]) -> bool {
    allowed
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

fn token_is_word(token: Option<&SqlToken>, value: &str) -> bool {
    matches!(token, Some(SqlToken::Word(word)) if word.eq_ignore_ascii_case(value))
}

fn token_identifier(token: Option<&SqlToken>) -> Option<String> {
    match token? {
        SqlToken::Word(value) | SqlToken::Identifier(value) => Some(value.clone()),
        SqlToken::StringLiteral(_) | SqlToken::Symbol(_) => None,
    }
}

fn balanced_parenthesized_end(tokens: &[SqlToken], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, token) in tokens.get(start..)?.iter().enumerate() {
        match token {
            SqlToken::Symbol('(') => depth = depth.checked_add(1)?,
            SqlToken::Symbol(')') => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(start + offset + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn valid_table_suffix(tokens: &[SqlToken]) -> bool {
    let mut cursor = 0;
    let mut without_rowid = false;
    let mut strict = false;
    while cursor < tokens.len() {
        if tokens.get(cursor) == Some(&SqlToken::Symbol(',')) {
            cursor += 1;
        } else if !without_rowid
            && token_is_word(tokens.get(cursor), "without")
            && token_is_word(tokens.get(cursor + 1), "rowid")
        {
            without_rowid = true;
            cursor += 2;
        } else if !strict && token_is_word(tokens.get(cursor), "strict") {
            strict = true;
            cursor += 1;
        } else {
            return false;
        }
    }
    true
}

fn tokenize_sql_statements(sql: &str) -> Option<Vec<Vec<SqlToken>>> {
    #[derive(Clone, Copy)]
    enum Mode {
        Normal,
        SingleQuote,
        DoubleQuote,
        Backtick,
        Bracket,
        LineComment,
        BlockComment,
    }
    let bytes = sql.as_bytes();
    let mut mode = Mode::Normal;
    let mut tokens = Vec::new();
    let mut token = Vec::new();
    let mut quoted = Vec::new();
    let mut index = 0;
    let flush_token = |token: &mut Vec<u8>, tokens: &mut Vec<SqlToken>| {
        if !token.is_empty() {
            tokens.push(SqlToken::Word(String::from_utf8_lossy(token).into_owned()));
            token.clear();
        }
    };
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match mode {
            Mode::Normal => match (byte, next) {
                (b'-', Some(b'-')) => {
                    flush_token(&mut token, &mut tokens);
                    mode = Mode::LineComment;
                    index += 1;
                }
                (b'/', Some(b'*')) => {
                    flush_token(&mut token, &mut tokens);
                    mode = Mode::BlockComment;
                    index += 1;
                }
                (b'\'', _) => {
                    flush_token(&mut token, &mut tokens);
                    quoted.clear();
                    mode = Mode::SingleQuote;
                }
                (b'"', _) => {
                    flush_token(&mut token, &mut tokens);
                    quoted.clear();
                    mode = Mode::DoubleQuote;
                }
                (b'`', _) => {
                    flush_token(&mut token, &mut tokens);
                    quoted.clear();
                    mode = Mode::Backtick;
                }
                (b'[', _) => {
                    flush_token(&mut token, &mut tokens);
                    quoted.clear();
                    mode = Mode::Bracket;
                }
                (b';', _) => {
                    flush_token(&mut token, &mut tokens);
                    tokens.push(SqlToken::Symbol(';'));
                }
                (b'(' | b')' | b',' | b'.' | b'=' | b'+' | b'-', _) => {
                    flush_token(&mut token, &mut tokens);
                    tokens.push(SqlToken::Symbol(byte as char));
                }
                _ if byte.is_ascii_alphanumeric() || byte == b'_' => token.push(byte),
                _ if byte.is_ascii_whitespace() => flush_token(&mut token, &mut tokens),
                _ if byte.is_ascii_punctuation() => {
                    flush_token(&mut token, &mut tokens);
                    tokens.push(SqlToken::Symbol(byte as char));
                }
                _ => return None,
            },
            Mode::SingleQuote => {
                if byte == b'\'' {
                    if next == Some(b'\'') {
                        quoted.push(b'\'');
                        index += 1;
                    } else {
                        mode = Mode::Normal;
                        tokens.push(SqlToken::StringLiteral(
                            String::from_utf8(quoted.clone()).ok()?,
                        ));
                    }
                } else {
                    quoted.push(byte);
                }
            }
            Mode::DoubleQuote => {
                if byte == b'"' {
                    if next == Some(b'"') {
                        quoted.push(b'"');
                        index += 1;
                    } else {
                        mode = Mode::Normal;
                        tokens.push(SqlToken::Identifier(
                            String::from_utf8(quoted.clone()).ok()?,
                        ));
                    }
                } else {
                    quoted.push(byte);
                }
            }
            Mode::Backtick => {
                if byte == b'`' {
                    if next == Some(b'`') {
                        quoted.push(b'`');
                        index += 1;
                    } else {
                        mode = Mode::Normal;
                        tokens.push(SqlToken::Identifier(
                            String::from_utf8(quoted.clone()).ok()?,
                        ));
                    }
                } else {
                    quoted.push(byte);
                }
            }
            Mode::Bracket => {
                if byte == b']' {
                    mode = Mode::Normal;
                    tokens.push(SqlToken::Identifier(
                        String::from_utf8(quoted.clone()).ok()?,
                    ));
                } else {
                    quoted.push(byte);
                }
            }
            Mode::LineComment => {
                if matches!(byte, b'\n' | b'\r') {
                    mode = Mode::Normal;
                }
            }
            Mode::BlockComment => {
                if byte == b'*' && next == Some(b'/') {
                    mode = Mode::Normal;
                    index += 1;
                }
            }
        }
        index += 1;
    }
    if !matches!(mode, Mode::Normal | Mode::LineComment) {
        return None;
    }
    flush_token(&mut token, &mut tokens);
    split_top_level_statements(tokens)
}

fn split_top_level_statements(tokens: Vec<SqlToken>) -> Option<Vec<Vec<SqlToken>>> {
    let mut statements = Vec::new();
    let mut current = Vec::new();
    let mut trigger = false;
    let mut trigger_body = false;
    let mut trigger_closed = false;
    let mut case_depth = 0usize;
    for token in tokens {
        if !trigger && create_trigger_prefix(&current, Some(&token)) {
            trigger = true;
        }
        if trigger && !trigger_body && token_is_word(Some(&token), "begin") {
            trigger_body = true;
        } else if trigger_body && !trigger_closed {
            if token_is_word(Some(&token), "case") {
                case_depth = case_depth.checked_add(1)?;
            } else if token_is_word(Some(&token), "end") {
                if case_depth > 0 {
                    case_depth -= 1;
                } else {
                    trigger_closed = true;
                }
            }
        }
        if token == SqlToken::Symbol(';') && (!trigger || trigger_closed) {
            if !current.is_empty() {
                statements.push(std::mem::take(&mut current));
            }
            trigger = false;
            trigger_body = false;
            trigger_closed = false;
            case_depth = 0;
        } else {
            current.push(token);
        }
    }
    if trigger && (!trigger_body || !trigger_closed || case_depth != 0) {
        return None;
    }
    if !current.is_empty() {
        statements.push(current);
    }
    Some(statements)
}

fn create_trigger_prefix(current: &[SqlToken], next: Option<&SqlToken>) -> bool {
    token_is_word(current.first(), "create")
        && ((current.len() == 1 && token_is_word(next, "trigger"))
            || (current.len() == 2
                && (token_is_word(current.get(1), "temp")
                    || token_is_word(current.get(1), "temporary"))
                && token_is_word(next, "trigger")))
}

fn build_fixed_query(
    migrations_table: &str,
    manifest_len: usize,
    object_names: &[String],
    table_names: &[String],
    proof_sha256: &str,
) -> FixedQuery {
    let mut sql = Vec::new();
    let mut statements = Vec::new();
    let ledger = BatchStatement::Ledger;
    sql.push(tagged_statement(
        &ledger,
        proof_sha256,
        &format!(
            "SELECT id, name FROM {} ORDER BY id LIMIT {}",
            quote_identifier(migrations_table),
            manifest_len + 1
        ),
        &[3],
    ));
    statements.push(ledger);
    let names = if object_names.is_empty() {
        String::from("NULL")
    } else {
        object_names
            .iter()
            .map(|name| quote_string(name))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let schema = BatchStatement::Schema;
    sql.push(tagged_statement(
        &schema,
        proof_sha256,
        &format!(
            "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name IN ({names}) ORDER BY type, name LIMIT {}",
            object_names.len() + 1
        ),
        &[3, 4],
    ));
    statements.push(schema);
    for table in table_names {
        let table_string = quote_string(table);
        let xinfo = BatchStatement::TableXinfo(table.clone());
        sql.push(tagged_statement(
            &xinfo,
            proof_sha256,
            &format!(
                "SELECT cid, name, type, \"notnull\", dflt_value, pk, hidden FROM pragma_table_xinfo({table_string}) ORDER BY cid LIMIT {}",
                MAX_COLUMNS_PER_TABLE + 1
            ),
            &[3],
        ));
        statements.push(xinfo);
        let foreign_keys = BatchStatement::ForeignKeyList(table.clone());
        sql.push(tagged_statement(
            &foreign_keys,
            proof_sha256,
            &format!(
                "SELECT id, seq, \"table\", \"from\", \"to\", on_update, on_delete, \"match\" FROM pragma_foreign_key_list({table_string}) ORDER BY id, seq LIMIT {}",
                MAX_FOREIGN_KEYS_PER_TABLE + 1
            ),
            &[3, 4],
        ));
        statements.push(foreign_keys);
        let foreign_key_check = BatchStatement::ForeignKeyCheck(table.clone());
        sql.push(tagged_statement(
            &foreign_key_check,
            proof_sha256,
            &format!(
                "SELECT \"table\", rowid, parent, fkid FROM pragma_foreign_key_check({table_string}) LIMIT 1"
            ),
            &[],
        ));
        statements.push(foreign_key_check);
    }
    let sql = sql.join(";\n");
    FixedQuery {
        sha256: sha256_bytes_hex(sql.as_bytes()),
        sql,
        proof_sha256: proof_sha256.to_string(),
        statements,
    }
}

fn tagged_statement(
    statement: &BatchStatement,
    proof_sha256: &str,
    data_sql: &str,
    data_order_positions: &[usize],
) -> String {
    let marker = quote_string(&statement.marker(proof_sha256));
    let null_fields = statement
        .data_fields()
        .iter()
        .map(|field| format!("NULL AS {}", quote_identifier(field)))
        .collect::<Vec<_>>()
        .join(", ");
    let mut order = vec!["2".to_string()];
    order.extend(data_order_positions.iter().map(ToString::to_string));
    format!(
        "SELECT {marker} AS \"__cf_mcp_statement_id\", 0 AS \"__cf_mcp_row_kind\", {null_fields} UNION ALL SELECT {marker}, 1, * FROM ({data_sql}) ORDER BY {}",
        order.join(", ")
    )
}

fn quote_identifier(value: &str) -> String {
    format!("\"{value}\"")
}

fn quote_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn parse_complete_batch(
    value: &Value,
    statements: &[BatchStatement],
    proof_sha256: &str,
    manifest: &[D1MigrationManifestEntry],
) -> Result<CanonicalSnapshot, CallToolResult> {
    let result_sets = value.as_array().ok_or_else(|| {
        reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_batch_malformed",
            "provider batch result was not a result-set array",
        )
    })?;
    if result_sets.len() != statements.len() {
        return Err(reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_batch_partial",
            "provider batch did not contain every fixed reconciliation result set exactly once",
        ));
    }
    let mut ledger = None;
    let mut schema_objects = None;
    let mut tables: BTreeMap<String, ObservedTable> = BTreeMap::new();
    for (result_set, statement) in result_sets.iter().zip(statements) {
        let rows = result_rows(result_set, statement, proof_sha256)?;
        match statement {
            BatchStatement::Ledger => {
                if rows.len() > manifest.len() {
                    return Err(reconciliation_error(
                        "contradictory",
                        "d1.migration_reconciliation_ledger_unbounded",
                        "migration ledger exceeded the exact manifest prefix bound",
                    ));
                }
                ledger = Some(parse_ledger_rows(&rows)?);
            }
            BatchStatement::Schema => {
                if rows.len() > MAX_SCHEMA_OBJECTS {
                    return Err(reconciliation_error(
                        "contradictory",
                        "d1.migration_reconciliation_schema_unbounded",
                        "sqlite_master evidence exceeded the declared object bound",
                    ));
                }
                schema_objects = Some(parse_schema_rows(&rows)?);
            }
            BatchStatement::TableXinfo(table) => {
                if rows.len() > MAX_COLUMNS_PER_TABLE {
                    return Err(reconciliation_error(
                        "contradictory",
                        "d1.migration_reconciliation_xinfo_unbounded",
                        "table_xinfo evidence exceeded the declared column bound",
                    ));
                }
                tables
                    .entry(table.clone())
                    .or_insert_with(|| ObservedTable {
                        name: table.clone(),
                        columns: Vec::new(),
                        foreign_keys: Vec::new(),
                    })
                    .columns = parse_column_rows(&rows)?;
            }
            BatchStatement::ForeignKeyList(table) => {
                if rows.len() > MAX_FOREIGN_KEYS_PER_TABLE {
                    return Err(reconciliation_error(
                        "contradictory",
                        "d1.migration_reconciliation_foreign_keys_unbounded",
                        "foreign_key_list evidence exceeded the declared definition bound",
                    ));
                }
                tables
                    .entry(table.clone())
                    .or_insert_with(|| ObservedTable {
                        name: table.clone(),
                        columns: Vec::new(),
                        foreign_keys: Vec::new(),
                    })
                    .foreign_keys = parse_foreign_key_rows(&rows)?;
            }
            BatchStatement::ForeignKeyCheck(table) => {
                if !rows.is_empty() {
                    let _ = table;
                    return Err(reconciliation_error(
                        "contradictory",
                        "d1.migration_reconciliation_foreign_key_violation",
                        "foreign_key_check reported a violation for a declared table",
                    ));
                }
            }
        }
    }
    Ok(CanonicalSnapshot {
        ledger: ledger.ok_or_else(|| {
            reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_ledger_missing",
                "complete batch omitted migration ledger evidence",
            )
        })?,
        schema_objects: schema_objects.ok_or_else(|| {
            reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_schema_missing",
                "complete batch omitted sqlite_master evidence",
            )
        })?,
        tables: tables.into_values().collect(),
    })
}

fn result_rows(
    result_set: &Value,
    statement: &BatchStatement,
    proof_sha256: &str,
) -> Result<Vec<Value>, CallToolResult> {
    let object = result_set.as_object().ok_or_else(|| {
        reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_result_malformed",
            "a reconciliation result set was not an object",
        )
    })?;
    if object.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_result_unsuccessful",
            "a reconciliation result set did not explicitly prove success",
        ));
    }
    match object.get("errors") {
        None | Some(Value::Array(_))
            if object
                .get("errors")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty) => {}
        _ => {
            return Err(reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_result_errors",
                "a reconciliation result set contained malformed or non-empty errors",
            ));
        }
    }
    let meta = object
        .get("meta")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_primary_evidence_contradictory",
                "provider result metadata did not prove that the fixed result set was served by the primary",
            )
        })?;
    if meta.get("served_by_primary") != Some(&Value::Bool(true)) {
        return Err(reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_primary_evidence_contradictory",
            "provider result metadata did not prove that the fixed result set was served by the primary",
        ));
    }
    let changed_db_valid = meta
        .get("changed_db")
        .is_none_or(|value| value == &Value::Bool(false));
    let exact_zero = |key: &str| meta.get(key).is_none_or(|value| value.as_i64() == Some(0));
    if !changed_db_valid || !exact_zero("changes") || !exact_zero("rows_written") {
        return Err(reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_read_only_meta_contradictory",
            "provider metadata was malformed or contradicted the internally constructed read-only batch",
        ));
    }
    let rows = object
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_rows_missing",
                "a reconciliation result set omitted its rows array",
            )
        })?;
    parse_tagged_rows(rows, statement, proof_sha256)
}

fn parse_tagged_rows(
    rows: &[Value],
    statement: &BatchStatement,
    proof_sha256: &str,
) -> Result<Vec<Value>, CallToolResult> {
    let first = rows.first().ok_or_else(|| {
        reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_statement_marker_missing",
            "a fixed reconciliation result omitted its mandatory statement identity marker",
        )
    })?;
    let first_object = first.as_object().ok_or_else(statement_marker_malformed)?;
    let marker = first_object
        .get("__cf_mcp_statement_id")
        .and_then(Value::as_str)
        .filter(|value| *value == statement.marker(proof_sha256))
        .ok_or_else(statement_marker_malformed)?;
    if first_object
        .get("__cf_mcp_row_kind")
        .and_then(Value::as_i64)
        != Some(0)
        || statement
            .data_fields()
            .iter()
            .any(|field| first_object.get(*field) != Some(&Value::Null))
    {
        return Err(statement_marker_malformed());
    }
    let expected_keys = statement
        .data_fields()
        .iter()
        .copied()
        .chain(["__cf_mcp_row_kind", "__cf_mcp_statement_id"])
        .collect::<BTreeSet<_>>();
    if first_object
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_keys
    {
        return Err(statement_marker_malformed());
    }

    let mut data_rows = Vec::with_capacity(rows.len().saturating_sub(1));
    for row in &rows[1..] {
        let object = row.as_object().ok_or_else(statement_marker_malformed)?;
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_keys
            || object.get("__cf_mcp_statement_id").and_then(Value::as_str) != Some(marker)
            || object.get("__cf_mcp_row_kind").and_then(Value::as_i64) != Some(1)
        {
            return Err(statement_marker_malformed());
        }
        let mut data = Map::new();
        for field in statement.data_fields() {
            data.insert(
                (*field).to_string(),
                object
                    .get(*field)
                    .cloned()
                    .ok_or_else(statement_marker_malformed)?,
            );
        }
        data_rows.push(Value::Object(data));
    }
    Ok(data_rows)
}

fn statement_marker_malformed() -> CallToolResult {
    reconciliation_error(
        "contradictory",
        "d1.migration_reconciliation_statement_marker_malformed",
        "a fixed reconciliation result had a missing, malformed, duplicate, or conflicting statement identity marker",
    )
}

fn parse_ledger_rows(rows: &[Value]) -> Result<Vec<D1ManifestLedgerRow>, CallToolResult> {
    let mut parsed = Vec::new();
    let mut previous_id = None;
    let mut names = BTreeSet::new();
    for row in rows {
        let object = exact_row(row, &["id", "name"])?;
        let id = object
            .get("id")
            .and_then(Value::as_i64)
            .filter(|id| *id >= 0);
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty() && name.len() <= 255 && !name.contains('\0'));
        let (id, name) = match (id, name) {
            (Some(id), Some(name)) => (id, name.to_string()),
            _ => {
                return Err(reconciliation_error(
                    "contradictory",
                    "d1.migration_reconciliation_ledger_malformed",
                    "migration ledger row did not contain an exact non-negative id and canonical name",
                ));
            }
        };
        if previous_id.is_some_and(|previous| previous >= id) || !names.insert(name.clone()) {
            return Err(reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_ledger_malformed",
                "migration ledger ids or names were duplicate or out of order",
            ));
        }
        previous_id = Some(id);
        parsed.push(D1ManifestLedgerRow { id, name });
    }
    Ok(parsed)
}

fn parse_schema_rows(rows: &[Value]) -> Result<Vec<ObservedSchemaObject>, CallToolResult> {
    let mut parsed = Vec::new();
    let mut names = BTreeSet::new();
    let mut previous = None::<(String, String)>;
    for row in rows {
        let object = exact_row(row, &["name", "sql", "tbl_name", "type"])?;
        let object_type = exact_string(object, "type")?;
        let name = exact_string(object, "name")?;
        let table_name = exact_string(object, "tbl_name")?;
        let sql = exact_string(object, "sql")?;
        let key = (object_type.clone(), name.clone());
        if !matches!(object_type.as_str(), "table" | "index" | "view" | "trigger")
            || !names.insert(name.clone())
            || previous.as_ref().is_some_and(|prior| prior >= &key)
        {
            return Err(reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_schema_malformed",
                "sqlite_master rows were duplicate, unexpected, or out of canonical order",
            ));
        }
        previous = Some(key);
        parsed.push(ObservedSchemaObject {
            object_type,
            name,
            table_name,
            sql_sha256: sha256_bytes_hex(sql.as_bytes()),
        });
    }
    Ok(parsed)
}

fn parse_column_rows(rows: &[Value]) -> Result<Vec<D1MigrationColumnExpectation>, CallToolResult> {
    let mut columns = Vec::new();
    for row in rows {
        let object = exact_row(
            row,
            &[
                "cid",
                "dflt_value",
                "hidden",
                "name",
                "notnull",
                "pk",
                "type",
            ],
        )?;
        columns.push(D1MigrationColumnExpectation {
            cid: exact_nonnegative_i64(object, "cid")?,
            name: exact_string(object, "name")?,
            declared_type: exact_string(object, "type")?,
            not_null: match object.get("notnull").and_then(Value::as_i64) {
                Some(0) => false,
                Some(1) => true,
                _ => return Err(malformed_xinfo()),
            },
            default_value: match object.get("dflt_value") {
                Some(Value::Null) => None,
                Some(Value::String(value)) => Some(value.clone()),
                _ => return Err(malformed_xinfo()),
            },
            primary_key_position: exact_nonnegative_i64(object, "pk")?,
            hidden: exact_nonnegative_i64(object, "hidden")?,
        });
    }
    validate_columns(&columns).map_err(|_| malformed_xinfo())?;
    Ok(columns)
}

fn malformed_xinfo() -> CallToolResult {
    reconciliation_error(
        "contradictory",
        "d1.migration_reconciliation_xinfo_malformed",
        "table_xinfo row was missing, malformed, duplicate, or out of order",
    )
}

fn parse_foreign_key_rows(
    rows: &[Value],
) -> Result<Vec<D1MigrationForeignKeyExpectation>, CallToolResult> {
    let mut foreign_keys = Vec::new();
    for row in rows {
        let object = exact_row(
            row,
            &[
                "from",
                "id",
                "match",
                "on_delete",
                "on_update",
                "seq",
                "table",
                "to",
            ],
        )?;
        foreign_keys.push(D1MigrationForeignKeyExpectation {
            id: exact_nonnegative_i64(object, "id")?,
            sequence: exact_nonnegative_i64(object, "seq")?,
            referenced_table: exact_string(object, "table")?,
            from_column: exact_string(object, "from")?,
            to_column: match object.get("to") {
                Some(Value::Null) => None,
                Some(Value::String(value)) => Some(value.clone()),
                _ => return Err(malformed_foreign_key()),
            },
            on_update: exact_string(object, "on_update")?,
            on_delete: exact_string(object, "on_delete")?,
            match_mode: exact_string(object, "match")?,
        });
    }
    validate_foreign_keys(&foreign_keys).map_err(|_| malformed_foreign_key())?;
    Ok(foreign_keys)
}

fn malformed_foreign_key() -> CallToolResult {
    reconciliation_error(
        "contradictory",
        "d1.migration_reconciliation_foreign_key_malformed",
        "foreign_key_list row was missing, malformed, duplicate, or out of order",
    )
}

fn exact_row<'a>(
    row: &'a Value,
    expected: &[&str],
) -> Result<&'a Map<String, Value>, CallToolResult> {
    let object = row.as_object().ok_or_else(|| {
        reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_row_malformed",
            "provider evidence row was not an object",
        )
    })?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_row_shape_unexpected",
            "provider evidence row had missing or unexpected fields",
        ));
    }
    Ok(object)
}

fn exact_string(object: &Map<String, Value>, key: &str) -> Result<String, CallToolResult> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| value.len() <= 16 * 1024 * 1024 && !value.contains('\0'))
        .map(str::to_string)
        .ok_or_else(|| {
            reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_row_value_malformed",
                "provider evidence row contained a missing or malformed string",
            )
        })
}

fn exact_nonnegative_i64(object: &Map<String, Value>, key: &str) -> Result<i64, CallToolResult> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .filter(|value| *value >= 0)
        .ok_or_else(|| {
            reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_row_value_malformed",
                "provider evidence row contained a missing or malformed integer",
            )
        })
}

fn verify_expected_state(
    expected: &D1MigrationStateExpectation,
    validated: &ValidatedExpectations,
    snapshot: &CanonicalSnapshot,
) -> Result<(), CallToolResult> {
    let expected_objects = expected
        .schema_objects
        .iter()
        .map(|object| ObservedSchemaObject {
            object_type: object.object_type.clone(),
            name: object.name.clone(),
            table_name: object.table_name.clone(),
            sql_sha256: object.sql_sha256.clone(),
        })
        .collect::<Vec<_>>();
    if snapshot.schema_objects != expected_objects {
        let code = if snapshot.schema_objects.is_empty() && !expected_objects.is_empty() {
            "d1.migration_reconciliation_schema_empty"
        } else {
            "d1.migration_reconciliation_schema_mismatch"
        };
        return Err(reconciliation_error(
            "contradictory",
            code,
            "stable sqlite_master object identity, type, parent, or exact SQL digest did not match the reviewed state",
        ));
    }
    let expected_tables = expected
        .tables
        .iter()
        .map(|table| {
            (
                table.name.clone(),
                ObservedTable {
                    name: table.name.clone(),
                    columns: table.columns.clone(),
                    foreign_keys: table.foreign_keys.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for table in &snapshot.tables {
        match expected_tables.get(&table.name) {
            Some(expected_table) if expected_table == table => {}
            None if table.columns.is_empty() && table.foreign_keys.is_empty() => {}
            Some(_) => {
                return Err(reconciliation_error(
                    "contradictory",
                    "d1.migration_reconciliation_table_proof_mismatch",
                    "stable table_xinfo or foreign_key_list evidence did not match the reviewed state",
                ));
            }
            None => {
                return Err(reconciliation_error(
                    "contradictory",
                    "d1.migration_reconciliation_unexpected_table_state",
                    "a table outside the selected reviewed state returned structural evidence",
                ));
            }
        }
    }
    if snapshot.tables.len() != validated.table_names.len()
        || expected_tables
            .keys()
            .any(|name| !snapshot.tables.iter().any(|table| &table.name == name))
    {
        return Err(reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_table_proof_missing",
            "stable batch omitted one or more declared table proof result sets",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_unique_original_prefix(
    account_id: &str,
    database_id: &str,
    family: &str,
    migrations_table: &str,
    manifest: &[D1MigrationManifestEntry],
    current_ledger: &[D1ManifestLedgerRow],
    approved_plan_sha256: &str,
) -> Result<usize, CallToolResult> {
    reconstruct_original_prefix_with(current_ledger.len(), approved_plan_sha256, |prefix| {
        d1_manifest_plan_sha256(
            account_id,
            database_id,
            family,
            migrations_table,
            manifest,
            &current_ledger[..prefix],
        )
    })
}

fn reconstruct_original_prefix_with<F>(
    max_prefix: usize,
    approved_plan_sha256: &str,
    digest: F,
) -> Result<usize, CallToolResult>
where
    F: Fn(usize) -> String,
{
    let matches = (0..=max_prefix)
        .filter(|prefix| digest(*prefix) == approved_plan_sha256)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [prefix] => Ok(*prefix),
        [] => Err(reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_plan_relationship_missing",
            "retained approved-plan digest did not match any exact current-ledger manifest prefix",
        )),
        _ => Err(reconciliation_error(
            "contradictory",
            "d1.migration_reconciliation_plan_relationship_nonunique",
            "retained approved-plan digest matched more than one manifest-prefix relationship",
        )),
    }
}

fn batch_digest(batch: &ParsedBatch) -> String {
    let bytes = serde_json::to_vec(&batch.snapshot)
        .expect("canonical reconciliation snapshot serialization is infallible");
    sha256_bytes_hex(&bytes)
}

fn response_digest_summary(batch: &ParsedBatch) -> Value {
    json!({
        "response_body_sha256": batch.response_body_sha256,
        "response_body_size_bytes": batch.response_body_size_bytes,
        "lifecycle": batch.lifecycle,
    })
}

fn response_digest_summary_from_adapter(batch: &D1MigrationReconciliationBatch) -> Value {
    json!({
        "response_body_sha256": batch.response_body_sha256,
        "response_body_size_bytes": batch.response_body_size_bytes,
        "lifecycle": batch.lifecycle,
    })
}

fn adapter_batch_error(
    failure: D1MigrationReconciliationBatchError,
    query_sha256: &str,
) -> CallToolResult {
    let lifecycle = failure.lifecycle;
    let capability_state =
        if failure.error.status.is_some_and(|status| {
            matches!(status, 401 | 403 | 429) || (500..=599).contains(&status)
        }) || matches!(
            failure.error.code,
            "cloudflare.timeout" | "cloudflare.transport_error" | "cloudflare.response_read_failed"
        ) {
            "unavailable"
        } else if failure.error.code == "cloudflare.config_missing_token"
            || failure.error.message.contains("pragma_")
            || failure.error.message.contains("not authorized")
            || failure.error.message.contains("SQLITE_AUTH")
        {
            "capability_gap"
        } else {
            "contradictory"
        };
    let response = match (
        failure.response_body_sha256,
        failure.response_body_size_bytes,
    ) {
        (Some(sha256), Some(size)) => vec![json!({
            "response_body_sha256": sha256,
            "response_body_size_bytes": size,
            "complete_body_digest": true,
            "lifecycle": lifecycle,
        })],
        (None, Some(size)) => vec![json!({
            "response_body_sha256": null,
            "response_body_size_bytes": size,
            "complete_body_digest": false,
            "lifecycle": lifecycle,
        })],
        _ => Vec::new(),
    };
    let mut result = reconciliation_error_with_evidence(
        capability_state,
        match capability_state {
            "capability_gap" => "d1.migration_reconciliation_query_capability_gap",
            "unavailable" => "d1.migration_reconciliation_provider_unavailable",
            _ => "d1.migration_reconciliation_provider_evidence_contradictory",
        },
        "provider could not return one complete strict read-only reconciliation batch",
        Some(query_sha256),
        &response,
    );
    if let Some(Value::Object(content)) = result.structured_content.as_mut() {
        content.insert("provider_read_lifecycle".to_string(), json!([lifecycle]));
        content.insert(
            "provider_calls".to_string(),
            json!(lifecycle.provider_calls()),
        );
        content.insert(
            "provider_cause".to_string(),
            json!({
                "code": failure.error.code,
                "status": failure.error.status,
                "retryable": false,
                "operator_guidance": "reconciliation_only",
            }),
        );
    }
    result
}

fn reconciliation_plan_sha256(
    account_id: &str,
    database_id: &str,
    family: &str,
    migrations_table: &str,
    manifest: &[D1MigrationManifestEntry],
    lease: &D1RetainedMigrationLeaseIdentity,
    original_prefix: usize,
    current_prefix: usize,
    outcome: &str,
    query_sha256: &str,
    snapshot_sha256: &str,
    effect_assertion_id: &str,
) -> String {
    let plan = json!({
        "version": 1,
        "operation": OPERATION,
        "target_key_sha256": sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes()),
        "database_id": database_id,
        "migration_family": family,
        "migrations_table": migrations_table,
        "manifest": d1_manifest_summaries(manifest),
        "lease": lease,
        "original_prefix_length": original_prefix,
        "current_prefix_length": current_prefix,
        "outcome": outcome,
        "query_sha256": query_sha256,
        "canonical_snapshot_sha256": snapshot_sha256,
        "effect_assertion_id": effect_assertion_id,
        "retry_decision": "do_not_retry_same_attempt",
        "lease_decision": "retain",
        "next_slice": "persist_terminal_reconciliation_receipt_then_guarded_retirement",
    });
    sha256_bytes_hex(
        &serde_json::to_vec(&plan)
            .expect("reconciliation transition plan serialization is infallible"),
    )
}

#[allow(clippy::too_many_arguments)]
fn reconciliation_plan_sha256_v1(
    account_id: &str,
    database_id: &str,
    family: &str,
    migrations_table: &str,
    manifest: &[D1MigrationManifestEntry],
    lease: &D1RetainedMigrationLeaseIdentity,
    original_prefix: usize,
    current_prefix: usize,
    outcome: &str,
    query_sha256: &str,
    snapshot_sha256: &str,
) -> String {
    let plan = json!({
        "version": 1,
        "operation": OPERATION,
        "target_key_sha256": sha256_bytes_hex(format!("{account_id}\0{database_id}").as_bytes()),
        "database_id": database_id,
        "migration_family": family,
        "migrations_table": migrations_table,
        "manifest": d1_manifest_summaries(manifest),
        "lease": lease,
        "original_prefix_length": original_prefix,
        "current_prefix_length": current_prefix,
        "outcome": outcome,
        "query_sha256": query_sha256,
        "canonical_snapshot_sha256": snapshot_sha256,
        "retry_decision": "do_not_retry_same_attempt",
        "lease_decision": "retain",
        "next_slice": "persist_terminal_reconciliation_receipt_then_guarded_retirement",
    });
    sha256_bytes_hex(
        &serde_json::to_vec(&plan)
            .expect("legacy reconciliation transition plan serialization is infallible"),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn replay_reconciliation_plan_sha256(
    account_id: &str,
    database_id: &str,
    family: &str,
    migrations_table: &str,
    manifest: &[D1MigrationManifestEntry],
    lease: &D1RetainedMigrationLeaseIdentity,
    original_prefix: usize,
    current_prefix: usize,
    outcome: &str,
    query_sha256: &str,
    snapshot_sha256: &str,
    effect_assertion_id: &str,
    legacy_v1: bool,
) -> String {
    if legacy_v1 {
        reconciliation_plan_sha256_v1(
            account_id,
            database_id,
            family,
            migrations_table,
            manifest,
            lease,
            original_prefix,
            current_prefix,
            outcome,
            query_sha256,
            snapshot_sha256,
        )
    } else {
        reconciliation_plan_sha256(
            account_id,
            database_id,
            family,
            migrations_table,
            manifest,
            lease,
            original_prefix,
            current_prefix,
            outcome,
            query_sha256,
            snapshot_sha256,
            effect_assertion_id,
        )
    }
}

fn contextualize_error(
    result: CallToolResult,
    query_sha256: Option<&str>,
    response_evidence: &[Value],
    prior_provider_calls: usize,
) -> CallToolResult {
    let mut content = result
        .structured_content
        .unwrap_or_else(|| json!({"ok": false, "error": {"code": "d1.migration_reconciliation_failed", "message": "reconciliation failed closed"}}));
    if let Value::Object(content) = &mut content {
        content.insert("operation".to_string(), json!(OPERATION));
        content.insert("dry_run".to_string(), json!(true));
        content.insert("read_only".to_string(), json!(true));
        content.insert(
            "retry_decision".to_string(),
            json!("do_not_retry_same_attempt"),
        );
        let custody_unverified =
            content.get("custody_status") == Some(&json!("retained_evidence_unverified"));
        if !custody_unverified {
            content.insert("lease_decision".to_string(), json!("retain"));
            content.insert("lease_retained".to_string(), json!(true));
            content.insert(
                "custody_status".to_string(),
                json!("retained_evidence_verified"),
            );
        }
        content.insert("query_sha256".to_string(), json!(query_sha256));
        let already_contains_prior = product_already_contains_prior_invocations(
            content,
            response_evidence,
            prior_provider_calls,
        );
        let provider_lifecycle = merge_provider_lifecycle_with_response_evidence(
            content,
            response_evidence,
            already_contains_prior,
        );
        prepend_response_evidence(content, response_evidence, already_contains_prior);
        content.insert(
            "provider_read_lifecycle".to_string(),
            Value::Array(provider_lifecycle.clone()),
        );
        content.insert("provider_mutations".to_string(), json!(0));
        content.insert("local_namespace_mutations".to_string(), json!(0));
        let current_provider_calls = content
            .get("provider_calls")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let provider_calls = if already_contains_prior {
            current_provider_calls
        } else {
            current_provider_calls.saturating_add(prior_provider_calls as u64)
        };
        content.insert("provider_calls".to_string(), json!(provider_calls));
    }
    CallToolResult::structured_error(content)
}

fn contextualize_unverified_custody_error(
    result: CallToolResult,
    query_sha256: Option<&str>,
    response_evidence: &[Value],
    provider_calls: usize,
) -> CallToolResult {
    let mut content = result
        .structured_content
        .unwrap_or_else(|| json!({"ok": false, "error": {"code": "d1.migration_reconciliation_failed", "message": "retained custody could not be revalidated"}}));
    if let Value::Object(content) = &mut content {
        content.insert("operation".to_string(), json!(OPERATION));
        content.insert("dry_run".to_string(), json!(true));
        content.insert("read_only".to_string(), json!(true));
        content.insert(
            "retry_decision".to_string(),
            json!("do_not_retry_same_attempt"),
        );
        content.insert("lease_decision".to_string(), json!("retain"));
        content.insert("lease_retained".to_string(), Value::Null);
        content.insert(
            "custody_status".to_string(),
            json!("retained_evidence_unverified"),
        );
        content.insert("query_sha256".to_string(), json!(query_sha256));
        let already_contains_prior =
            product_already_contains_prior_invocations(content, response_evidence, provider_calls);
        let provider_lifecycle = merge_provider_lifecycle_with_response_evidence(
            content,
            response_evidence,
            already_contains_prior,
        );
        prepend_response_evidence(content, response_evidence, already_contains_prior);
        content.insert(
            "provider_read_lifecycle".to_string(),
            Value::Array(provider_lifecycle),
        );
        content.insert("provider_calls".to_string(), json!(provider_calls));
        content.insert("provider_mutations".to_string(), json!(0));
        content.insert("local_namespace_mutations".to_string(), json!(0));
    }
    CallToolResult::structured_error(content)
}

fn contextualize_provider_error_with_unverified_custody(
    provider_error: CallToolResult,
    custody_error: CallToolResult,
    query_sha256: Option<&str>,
    provider_calls: usize,
) -> CallToolResult {
    let custody_cause = custody_error
        .structured_content
        .as_ref()
        .and_then(|content| content.get("error"))
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "code": "d1.migration_reconciliation_custody_revalidation_failed",
                "message": "retained custody could not be revalidated after the provider call",
            })
        });
    let mut result =
        contextualize_unverified_custody_error(provider_error, query_sha256, &[], provider_calls);
    if let Some(Value::Object(content)) = result.structured_content.as_mut() {
        content.insert("custody_cause".to_string(), custody_cause);
    }
    result
}

fn prepend_response_evidence(
    content: &mut serde_json::Map<String, Value>,
    prior: &[Value],
    already_contains_prior: bool,
) {
    if prior.is_empty() {
        content
            .entry("response_evidence".to_string())
            .or_insert_with(|| json!([]));
        return;
    }
    let current = content
        .get("response_evidence")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut merged = if already_contains_prior {
        current
    } else {
        let mut merged = prior.to_vec();
        merged.extend(current);
        merged
    };
    merged.shrink_to_fit();
    content.insert("response_evidence".to_string(), Value::Array(merged));
}

fn response_evidence_lifecycle(response_evidence: &[Value]) -> Vec<Value> {
    response_evidence
        .iter()
        .filter_map(|evidence| evidence.get("lifecycle").cloned())
        .collect()
}

fn product_already_contains_prior_invocations(
    content: &serde_json::Map<String, Value>,
    prior_response_evidence: &[Value],
    prior_provider_calls: usize,
) -> bool {
    if prior_response_evidence.is_empty() {
        return false;
    }
    let prior_lifecycle = response_evidence_lifecycle(prior_response_evidence);
    let current_response_evidence = content
        .get("response_evidence")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let current_lifecycle = content
        .get("provider_read_lifecycle")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let current_provider_calls = content
        .get("provider_calls")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let positional_growth = current_response_evidence.len() > prior_response_evidence.len()
        || current_lifecycle.len() > prior_lifecycle.len()
        || current_provider_calls > prior_provider_calls as u64;
    positional_growth
        && current_response_evidence.starts_with(prior_response_evidence)
        && current_lifecycle.starts_with(&prior_lifecycle)
}

fn lifecycle_covers_body_evidence_without_stale_reads(
    body_evidence: &[Value],
    lifecycle: &[Value],
) -> bool {
    let mut body_evidence = body_evidence.iter().peekable();
    for invocation in lifecycle {
        if body_evidence
            .peek()
            .is_some_and(|evidence| *evidence == invocation)
        {
            body_evidence.next();
        } else if invocation.get("body_stage").and_then(Value::as_str) != Some("not_read") {
            return false;
        }
    }
    body_evidence.next().is_none()
}

fn merge_provider_lifecycle_with_response_evidence(
    content: &serde_json::Map<String, Value>,
    prior_response_evidence: &[Value],
    already_contains_prior: bool,
) -> Vec<Value> {
    let prior_lifecycle = response_evidence_lifecycle(prior_response_evidence);
    let current_response_evidence = content
        .get("response_evidence")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let current_evidence_lifecycle = response_evidence_lifecycle(current_response_evidence);
    let current_lifecycle = content
        .get("provider_read_lifecycle")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let current_attempted_calls = current_lifecycle
        .iter()
        .filter(|lifecycle| {
            lifecycle.get("dispatch_stage").and_then(Value::as_str) == Some("attempted")
        })
        .count() as u64;
    let current_recorded_calls = content.get("provider_calls").and_then(Value::as_u64);
    let current_lifecycle_is_consistent = current_recorded_calls.is_some_and(|calls| {
        (calls == current_attempted_calls || calls == current_lifecycle.len() as u64)
            && lifecycle_covers_body_evidence_without_stale_reads(
                &current_evidence_lifecycle,
                &current_lifecycle,
            )
    });
    let current_lifecycle = if current_lifecycle_is_consistent {
        current_lifecycle
    } else {
        current_evidence_lifecycle
    };
    if already_contains_prior {
        current_lifecycle
    } else {
        let mut merged = prior_lifecycle;
        merged.extend(current_lifecycle);
        merged
    }
}

fn prelease_error(
    result: CallToolResult,
    custody_status: &'static str,
    query_sha256: Option<&str>,
) -> CallToolResult {
    let mut content = result
        .structured_content
        .unwrap_or_else(|| json!({"ok": false, "error": {"code": "d1.migration_reconciliation_failed", "message": "reconciliation failed before custody acquisition"}}));
    if let Value::Object(content) = &mut content {
        content.insert("operation".to_string(), json!(OPERATION));
        content.insert("dry_run".to_string(), json!(true));
        content.insert("read_only".to_string(), json!(true));
        content.insert("lease_decision".to_string(), json!("not_acquired"));
        content.insert("lease_retained".to_string(), Value::Null);
        content.insert("custody_status".to_string(), json!(custody_status));
        content.insert("query_sha256".to_string(), json!(query_sha256));
        content.insert("provider_calls".to_string(), json!(0));
        content.insert("provider_read_lifecycle".to_string(), json!([]));
        content.insert("provider_mutations".to_string(), json!(0));
        content.insert("local_namespace_mutations".to_string(), json!(0));
    }
    CallToolResult::structured_error(content)
}

fn reconciliation_error(
    capability_state: &'static str,
    code: &'static str,
    message: &'static str,
) -> CallToolResult {
    reconciliation_error_with_evidence(capability_state, code, message, None, &[])
}

fn reconciliation_error_with_evidence(
    capability_state: &'static str,
    code: &'static str,
    message: &'static str,
    query_sha256: Option<&str>,
    response_evidence: &[Value],
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": OPERATION,
        "dry_run": true,
        "read_only": true,
        "status": "reconciliation_required",
        "outcome": "unknown",
        "capability_state": capability_state,
        "retry_decision": "do_not_retry_same_attempt",
        "lease_decision": "not_acquired",
        "lease_retained": null,
        "custody_status": "not_inspected",
        "query_sha256": query_sha256,
        "response_evidence": response_evidence,
        "provider_mutations": 0,
        "local_namespace_mutations": 0,
        "error": {
            "code": code,
            "message": message,
            "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result."
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROOF: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // DevSkim: ignore DS173237 -- synthetic SHA-256 fixture, not a credential
    const SECOND_PROOF: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; // DevSkim: ignore DS173237 -- synthetic SHA-256 fixture, not a credential

    fn manifest(sql: &str) -> Vec<D1MigrationManifestEntry> {
        vec![D1MigrationManifestEntry {
            name: "0001_create.sql".to_string(),
            size_bytes: sql.len() as u64,
            sql_sha256: sha256_bytes_hex(sql.as_bytes()),
            sql: sql.to_string(),
        }]
    }

    fn empty_state() -> D1MigrationStateExpectation {
        D1MigrationStateExpectation {
            manifest_prefix_length: 0,
            schema_objects: Vec::new(),
            tables: Vec::new(),
        }
    }

    fn tagged_result(
        statement: &BatchStatement,
        proof_sha256: &str,
        rows: Vec<Value>,
        meta: Option<Value>,
    ) -> Value {
        let marker = statement.marker(proof_sha256);
        let mut tagged = Vec::new();
        let mut sentinel = Map::new();
        sentinel.insert("__cf_mcp_statement_id".to_string(), json!(marker));
        sentinel.insert("__cf_mcp_row_kind".to_string(), json!(0));
        for field in statement.data_fields() {
            sentinel.insert((*field).to_string(), Value::Null);
        }
        tagged.push(Value::Object(sentinel));
        for row in rows {
            let mut row = row.as_object().expect("test data row").clone();
            row.insert("__cf_mcp_statement_id".to_string(), json!(marker));
            row.insert("__cf_mcp_row_kind".to_string(), json!(1));
            tagged.push(Value::Object(row));
        }
        let mut meta = meta.unwrap_or_else(|| json!({}));
        meta.as_object_mut()
            .expect("test result metadata object")
            .entry("served_by_primary".to_string())
            .or_insert_with(|| json!(true));
        let mut result = json!({"success": true, "results": tagged});
        result
            .as_object_mut()
            .expect("test result object")
            .insert("meta".to_string(), meta);
        result
    }

    #[test]
    fn registry_rejects_missing_and_non_schema_effect_proof() {
        let create = manifest("CREATE TABLE items(id INTEGER PRIMARY KEY);");
        assert!(derive_effect_assertion(None, &create).is_err());
        assert!(
            derive_effect_assertion(
                Some(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1),
                &manifest("INSERT INTO items(id) VALUES (1);")
            )
            .is_err()
        );
        assert!(
            derive_effect_assertion(Some(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1), &create).is_ok()
        );
        for sql in [
            "CREATE TABLE items AS VALUES (1);",
            "CREATE TABLE items AS SELECT 1;",
            "CREATE VIRTUAL TABLE items USING fts5(value);",
            "CREATE VIEW items AS SELECT 1;",
            "CREATE TRIGGER items AFTER INSERT ON source BEGIN SELECT 1; END;",
        ] {
            assert!(
                derive_effect_assertion(
                    Some(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1),
                    &manifest(sql)
                )
                .is_err(),
                "must reject data-producing or non-schema-only CREATE: {sql}"
            );
        }
    }

    #[test]
    fn extended_registry_derives_views_and_complete_trigger_bodies() {
        let sql = r#"
            CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT, touched INTEGER);
            CREATE INDEX items_by_name ON items(name);
            CREATE VIEW item_names AS SELECT id, name FROM items;
            CREATE TRIGGER items_after_update AFTER UPDATE OF name ON items
            WHEN NEW.name IS NOT OLD.name
            BEGIN
                INSERT INTO item_audit(item_id, value)
                VALUES (NEW.id, CASE WHEN NEW.name = '' THEN 'empty' ELSE NEW.name END);
                UPDATE items SET touched = 1 WHERE id = NEW.id;
            END;
        "#;
        let derived = derive_effect_assertion(
            Some(EFFECT_ASSERTION_SCHEMA_CREATE_OBJECTS_V1),
            &manifest(sql),
        )
        .expect("derive table, index, view, and whole trigger");
        assert_eq!(
            derived[1],
            vec![
                DerivedSchemaObject {
                    object_type: "index".to_string(),
                    name: "items_by_name".to_string(),
                    table_name: "items".to_string(),
                },
                DerivedSchemaObject {
                    object_type: "table".to_string(),
                    name: "items".to_string(),
                    table_name: "items".to_string(),
                },
                DerivedSchemaObject {
                    object_type: "trigger".to_string(),
                    name: "items_after_update".to_string(),
                    table_name: "items".to_string(),
                },
                DerivedSchemaObject {
                    object_type: "view".to_string(),
                    name: "item_names".to_string(),
                    table_name: "item_names".to_string(),
                },
            ]
        );
        assert!(
            derive_effect_assertion(Some(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1), &manifest(sql))
                .is_err(),
            "the backward-compatible assertion must keep rejecting view/trigger effects",
        );
    }

    #[test]
    fn extended_registry_rejects_unsupported_and_malformed_effects() {
        for sql in [
            "CREATE TEMP VIEW item_names AS SELECT id FROM items;",
            "CREATE TEMPORARY TRIGGER item_change AFTER UPDATE ON items BEGIN SELECT 1; END;",
            "CREATE VIEW main.item_names AS SELECT id FROM items;",
            "CREATE TRIGGER main.item_change AFTER UPDATE ON items BEGIN SELECT 1; END;",
            "CREATE TRIGGER item_change AFTER UPDATE ON main.items BEGIN SELECT 1; END;",
            "CREATE TABLE items AS SELECT 1;",
            "CREATE VIRTUAL TABLE items USING fts5(value);",
            "INSERT INTO items(id) VALUES (1);",
            "ALTER TABLE items ADD COLUMN name TEXT;",
            "DROP TABLE items;",
            "PRAGMA foreign_keys = ON;",
            "CREATE VIEW item_names AS DELETE FROM items;",
            "CREATE TRIGGER item_change AFTER SELECT ON items BEGIN SELECT 1; END;",
            "CREATE TRIGGER item_change AFTER UPDATE ON items BEGIN SELECT 'unterminated; END;",
            "CREATE TRIGGER item_change AFTER UPDATE ON items BEGIN SELECT 1; /* unclosed",
            "CREATE TRIGGER item_change AFTER UPDATE ON items BEGIN SELECT CASE WHEN 1 THEN 1 END;",
            "CREATE TRIGGER item_change AFTER UPDATE ON items BEGIN END;",
            "CREATE TRIGGER item_change AFTER UPDATE ON items; DELETE FROM items; BEGIN SELECT 1; END;",
            "CREATE TRIGGER item_change AFTER UPDATE ON items BEGIN CREATE TABLE hidden(id); END;",
            "CREATE TRIGGER item_change AFTER UPDATE ON items BEGIN PRAGMA foreign_keys; END;",
            "CREATE TRIGGER item_change AFTER UPDATE ON items WHEN BEGIN SELECT 1; END;",
        ] {
            assert!(
                derive_effect_assertion(
                    Some(EFFECT_ASSERTION_SCHEMA_CREATE_OBJECTS_V1),
                    &manifest(sql),
                )
                .is_err(),
                "unsupported or malformed effect must fail closed: {sql}",
            );
        }

        let first_trigger = "CREATE TRIGGER item_change AFTER UPDATE ON items BEGIN SELECT 1; END;";
        let second_trigger =
            "CREATE TRIGGER item_change AFTER UPDATE ON items BEGIN SELECT 2; END;";
        let repeated = vec![
            D1MigrationManifestEntry {
                name: "0001.sql".to_string(),
                size_bytes: first_trigger.len() as u64,
                sql_sha256: sha256_bytes_hex(first_trigger.as_bytes()),
                sql: first_trigger.to_string(),
            },
            D1MigrationManifestEntry {
                name: "0002.sql".to_string(),
                size_bytes: second_trigger.len() as u64,
                sql_sha256: sha256_bytes_hex(second_trigger.as_bytes()),
                sql: second_trigger.to_string(),
            },
        ];
        assert!(
            derive_effect_assertion(Some(EFFECT_ASSERTION_SCHEMA_CREATE_OBJECTS_V1), &repeated)
                .is_err(),
            "a CREATE identity cannot be reused in a later prefix",
        );
        assert!(
            derive_effect_assertion(
                Some(EFFECT_ASSERTION_SCHEMA_CREATE_OBJECTS_V1),
                &manifest(
                    "CREATE TABLE shared_name(id INTEGER); CREATE VIEW shared_name AS SELECT id FROM shared_name;",
                ),
            )
            .is_err(),
            "schema identities cannot be reused across object types",
        );
    }

    #[test]
    fn additive_registry_derives_baseline_parent_and_mixed_exact_prefixes() {
        let first = "PRAGMA foreign_keys = ON; ALTER TABLE items ADD COLUMN status TEXT;";
        let second = "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE INDEX audit_by_id ON audit(id); CREATE VIEW audit_ids AS SELECT id FROM audit; CREATE TRIGGER audit_after_insert AFTER INSERT ON audit BEGIN SELECT 1; END;";
        let manifest = vec![
            D1MigrationManifestEntry {
                name: "0001_add.sql".to_string(),
                size_bytes: first.len() as u64,
                sql_sha256: sha256_bytes_hex(first.as_bytes()),
                sql: first.to_string(),
            },
            D1MigrationManifestEntry {
                name: "0002_create.sql".to_string(),
                size_bytes: second.len() as u64,
                sql_sha256: sha256_bytes_hex(second.as_bytes()),
                sql: second.to_string(),
            },
        ];
        let derived =
            derive_effect_assertion_details(Some(EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1), &manifest)
                .expect("derive additive mixed prefixes");
        validate_reserved_migrations_table("d1_migrations", &derived)
            .expect("an unrelated additive trigger must not conflict with the reserved ledger");
        assert_eq!(
            derived.states,
            vec![
                vec![DerivedSchemaObject {
                    object_type: "table".to_string(),
                    name: "items".to_string(),
                    table_name: "items".to_string(),
                }],
                vec![DerivedSchemaObject {
                    object_type: "table".to_string(),
                    name: "items".to_string(),
                    table_name: "items".to_string(),
                }],
                vec![
                    DerivedSchemaObject {
                        object_type: "index".to_string(),
                        name: "audit_by_id".to_string(),
                        table_name: "audit".to_string(),
                    },
                    DerivedSchemaObject {
                        object_type: "table".to_string(),
                        name: "audit".to_string(),
                        table_name: "audit".to_string(),
                    },
                    DerivedSchemaObject {
                        object_type: "table".to_string(),
                        name: "items".to_string(),
                        table_name: "items".to_string(),
                    },
                    DerivedSchemaObject {
                        object_type: "trigger".to_string(),
                        name: "audit_after_insert".to_string(),
                        table_name: "audit".to_string(),
                    },
                    DerivedSchemaObject {
                        object_type: "view".to_string(),
                        name: "audit_ids".to_string(),
                        table_name: "audit_ids".to_string(),
                    },
                ],
            ],
        );
        let plan = derived.additive_plan.expect("additive plan");
        assert!(plan.prefixes[0].foreign_keys_on);
        assert_eq!(
            plan.prefixes[0]
                .addition
                .as_ref()
                .expect("one addition")
                .column
                .name,
            "status",
        );
        assert_eq!(
            plan.prefixes[1].created_objects,
            BTreeSet::from([
                ("index".to_string(), "audit_by_id".to_string()),
                ("table".to_string(), "audit".to_string()),
                ("trigger".to_string(), "audit_after_insert".to_string()),
                ("view".to_string(), "audit_ids".to_string()),
            ]),
        );

        assert!(
            derive_effect_assertion(Some(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1), &manifest,)
                .is_err(),
            "the legacy table/index assertion remains unchanged",
        );
        assert!(
            derive_effect_assertion(Some(EFFECT_ASSERTION_SCHEMA_CREATE_OBJECTS_V1), &manifest,)
                .is_err(),
            "the view/trigger assertion remains unchanged",
        );
    }

    #[test]
    fn additive_registry_rejects_unsupported_ddl_and_pragma_before_expectations() {
        for sql in [
            "ALTER TABLE items RENAME TO renamed;",
            "ALTER TABLE items DROP COLUMN status;",
            "ALTER TABLE items ADD COLUMN first TEXT, ADD COLUMN second TEXT;",
            "ALTER TABLE main.items ADD COLUMN status TEXT;",
            "ALTER TABLE items ADD COLUMN status TEXT REFERENCES other(id);",
            "PRAGMA foreign_keys(ON);",
            "PRAGMA main.foreign_keys = ON;",
            "PRAGMA foreign_keys = OFF;",
            "PRAGMA journal_mode = WAL;",
        ] {
            assert!(
                derive_effect_assertion(Some(EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1), &manifest(sql),)
                    .is_err(),
                "unsupported additive effect must fail closed: {sql}",
            );
        }

        let create_and_add_same_prefix =
            "CREATE TABLE items(id INTEGER); ALTER TABLE items ADD COLUMN status TEXT;";
        assert!(
            derive_effect_assertion(
                Some(EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1),
                &manifest(create_and_add_same_prefix),
            )
            .is_err(),
            "a parent must exist in baseline or an earlier observable prefix",
        );

        let manifest_entries = |sql_entries: &[&str]| {
            sql_entries
                .iter()
                .enumerate()
                .map(|(index, sql)| D1MigrationManifestEntry {
                    name: format!("{:04}.sql", index + 1),
                    size_bytes: sql.len() as u64,
                    sql_sha256: sha256_bytes_hex(sql.as_bytes()),
                    sql: (*sql).to_string(),
                })
                .collect::<Vec<_>>()
        };
        let create_then_add = manifest_entries(&[
            "CREATE TABLE items(id INTEGER);",
            "PRAGMA foreign_keys = ON; ALTER TABLE items ADD status TEXT DEFAULT 'ready';",
        ]);
        let derived = derive_effect_assertion_details(
            Some(EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1),
            &create_then_add,
        )
        .expect("a table created in an earlier prefix may be altered later");
        assert_eq!(derived.states[0], Vec::new());
        assert_eq!(derived.states[1], derived.states[2]);
        assert_eq!(
            derived
                .additive_plan
                .expect("additive transition plan")
                .prefixes[1]
                .addition
                .as_ref()
                .expect("later add")
                .column
                .default_value
                .as_deref(),
            Some("'ready'")
        );

        let add_then_create = manifest_entries(&[
            "ALTER TABLE items ADD COLUMN status TEXT;",
            "CREATE TABLE items(id INTEGER);",
        ]);
        assert!(
            derive_effect_assertion(Some(EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1), &add_then_create,)
                .is_err(),
            "a later CREATE cannot retroactively establish an additive baseline parent",
        );
    }

    #[test]
    fn additive_registry_accepts_only_bounded_column_local_check_expressions() {
        for sql in [
            "ALTER TABLE records ADD COLUMN token TEXT CHECK (token IS NULL OR (length(token)=35 AND substr(token,1,3)='pre'));",
            "ALTER TABLE records ADD COLUMN state TEXT NOT NULL DEFAULT 'x' CHECK (state='x');",
            "ALTER TABLE records ADD COLUMN kind TEXT NOT NULL DEFAULT 'x' CHECK (kind IN ('x','y'));",
        ] {
            derive_effect_assertion(Some(EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1), &manifest(sql))
                .unwrap_or_else(|_| panic!("bounded CHECK must classify: {sql}"));
        }

        for sql in [
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (EXISTS (SELECT 1));",
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (other_column='x');",
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (lower(state)='x');",
            "ALTER TABLE records ADD COLUMN state TEXT CHECK ((state='x');",
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (((((((state='x')))))));",
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (state!='x');",
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (state='x') REFERENCES parent(id);",
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (state='x'); DELETE FROM records;",
        ] {
            assert!(
                derive_effect_assertion(Some(EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1), &manifest(sql))
                    .is_err(),
                "hostile or unsupported CHECK must fail closed: {sql}",
            );
        }
    }

    #[test]
    fn view_and_trigger_expectations_bind_exact_rows_without_structural_table_proofs() {
        let derived = vec![
            Vec::new(),
            vec![
                DerivedSchemaObject {
                    object_type: "table".to_string(),
                    name: "items".to_string(),
                    table_name: "items".to_string(),
                },
                DerivedSchemaObject {
                    object_type: "trigger".to_string(),
                    name: "item_change".to_string(),
                    table_name: "items".to_string(),
                },
                DerivedSchemaObject {
                    object_type: "view".to_string(),
                    name: "item_names".to_string(),
                    table_name: "item_names".to_string(),
                },
            ],
        ];
        let table = D1MigrationTableExpectation {
            name: "items".to_string(),
            columns: vec![D1MigrationColumnExpectation {
                cid: 0,
                name: "id".to_string(),
                declared_type: "INTEGER".to_string(),
                not_null: false,
                default_value: None,
                primary_key_position: 1,
                hidden: 0,
            }],
            foreign_keys: Vec::new(),
        };
        let expected = D1MigrationStateExpectation {
            manifest_prefix_length: 1,
            schema_objects: vec![
                D1MigrationSchemaObjectExpectation {
                    object_type: "table".to_string(),
                    name: "items".to_string(),
                    table_name: "items".to_string(),
                    sql_sha256: "a".repeat(64),
                },
                D1MigrationSchemaObjectExpectation {
                    object_type: "trigger".to_string(),
                    name: "item_change".to_string(),
                    table_name: "items".to_string(),
                    sql_sha256: "b".repeat(64),
                },
                D1MigrationSchemaObjectExpectation {
                    object_type: "view".to_string(),
                    name: "item_names".to_string(),
                    table_name: "item_names".to_string(),
                    sql_sha256: "c".repeat(64),
                },
            ],
            tables: vec![table.clone()],
        };
        let validated = validate_expectations(&derived, vec![empty_state(), expected.clone()])
            .expect("only the physical table needs xinfo/FK expectations");
        assert_eq!(validated.table_names, vec!["items"]);

        let mut omitted = expected.clone();
        omitted.schema_objects.remove(1);
        assert!(
            validate_expectations(&derived, vec![empty_state(), omitted]).is_err(),
            "a trigger omitted from a selected prefix must fail before provider access",
        );

        let mut added = expected.clone();
        added
            .schema_objects
            .push(D1MigrationSchemaObjectExpectation {
                object_type: "view".to_string(),
                name: "unexpected_view".to_string(),
                table_name: "unexpected_view".to_string(),
                sql_sha256: "e".repeat(64),
            });
        assert!(
            validate_expectations(&derived, vec![empty_state(), added]).is_err(),
            "an added schema object must fail before provider access",
        );

        let mut wrong_parent = expected.clone();
        wrong_parent.schema_objects[1].table_name = "other_items".to_string();
        assert!(
            validate_expectations(&derived, vec![empty_state(), wrong_parent]).is_err(),
            "a trigger parent mismatch must fail before provider access",
        );

        let orphan_derived = vec![
            Vec::new(),
            vec![DerivedSchemaObject {
                object_type: "trigger".to_string(),
                name: "orphan_trigger".to_string(),
                table_name: "missing_table".to_string(),
            }],
        ];
        let orphan_expected = D1MigrationStateExpectation {
            manifest_prefix_length: 1,
            schema_objects: vec![D1MigrationSchemaObjectExpectation {
                object_type: "trigger".to_string(),
                name: "orphan_trigger".to_string(),
                table_name: "missing_table".to_string(),
                sql_sha256: "f".repeat(64),
            }],
            tables: Vec::new(),
        };
        let orphan_error =
            validate_expectations(&orphan_derived, vec![empty_state(), orphan_expected])
                .expect_err("a trigger cannot bind an absent table");
        assert_eq!(
            orphan_error
                .structured_content
                .expect("structured trigger-parent error")["error"]["code"],
            "d1.migration_reconciliation_trigger_parent_missing",
        );

        let snapshot = CanonicalSnapshot {
            ledger: vec![],
            schema_objects: vec![
                ObservedSchemaObject {
                    object_type: "table".to_string(),
                    name: "items".to_string(),
                    table_name: "items".to_string(),
                    sql_sha256: "a".repeat(64),
                },
                ObservedSchemaObject {
                    object_type: "trigger".to_string(),
                    name: "item_change".to_string(),
                    table_name: "items".to_string(),
                    sql_sha256: "d".repeat(64),
                },
                ObservedSchemaObject {
                    object_type: "view".to_string(),
                    name: "item_names".to_string(),
                    table_name: "item_names".to_string(),
                    sql_sha256: "c".repeat(64),
                },
            ],
            tables: vec![ObservedTable {
                name: "items".to_string(),
                columns: table.columns,
                foreign_keys: Vec::new(),
            }],
        };
        assert!(
            verify_expected_state(&expected, &validated, &snapshot).is_err(),
            "a wrong sqlite_master SQL digest must not converge",
        );
    }

    #[test]
    fn derived_schema_requires_complete_prefix_expectations() {
        let create = manifest("CREATE TABLE items(id INTEGER PRIMARY KEY);");
        let derived =
            derive_effect_assertion(Some(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1), &create)
                .expect("derive exact CREATE target");
        assert!(validate_expectations(&derived, vec![empty_state()]).is_err());

        let mut omitted = empty_state();
        omitted.manifest_prefix_length = 1;
        assert!(
            validate_expectations(&derived, vec![empty_state(), omitted]).is_err(),
            "caller omission cannot produce a converged schema proof"
        );

        let mixed_case = manifest("CrEaTe TaBlE Items(id INTEGER PRIMARY KEY);");
        let mixed_case_derived =
            derive_effect_assertion(Some(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1), &mixed_case)
                .expect("derive case-insensitive keyword with exact identifier");
        assert_eq!(mixed_case_derived[1][0].name, "Items");
    }

    #[test]
    fn preprovider_failures_emit_closed_zero_call_lifecycle_evidence() {
        for (custody_status, query_sha256) in
            [("not_inspected", None), ("inspection_failed", Some(PROOF))]
        {
            let result = prelease_error(
                reconciliation_error(
                    "capability_gap",
                    "d1.migration_reconciliation_synthetic_preprovider_failure",
                    "synthetic pre-provider failure",
                ),
                custody_status,
                query_sha256,
            );
            let content = result
                .structured_content
                .expect("structured pre-provider failure");
            assert_eq!(
                content,
                json!({
                    "ok": false,
                    "operation": "d1_reconcile_migration_manifest",
                    "dry_run": true,
                    "read_only": true,
                    "status": "reconciliation_required",
                    "outcome": "unknown",
                    "capability_state": "capability_gap",
                    "retry_decision": "do_not_retry_same_attempt",
                    "lease_decision": "not_acquired",
                    "lease_retained": null,
                    "custody_status": custody_status,
                    "query_sha256": query_sha256,
                    "response_evidence": [],
                    "provider_calls": 0,
                    "provider_read_lifecycle": [],
                    "provider_mutations": 0,
                    "local_namespace_mutations": 0,
                    "error": {
                        "code": "d1.migration_reconciliation_synthetic_preprovider_failure",
                        "message": "synthetic pre-provider failure",
                        "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result."
                    }
                })
            );
        }
    }

    #[test]
    fn plan_reconstruction_requires_unique_exact_prefix() {
        assert_eq!(
            reconstruct_original_prefix_with(2, "match", |prefix| if prefix == 1 {
                "match".to_string()
            } else {
                "miss".to_string()
            })
            .expect("unique prefix"),
            1
        );
        assert!(reconstruct_original_prefix_with(2, "match", |_| "miss".to_string()).is_err());
        assert!(reconstruct_original_prefix_with(2, "match", |_| "match".to_string()).is_err());
    }

    #[test]
    fn fixed_query_contains_only_bounded_internal_selects() {
        let query = build_fixed_query(
            "d1_migrations",
            2,
            &["items".to_string(), "items_by_name".to_string()],
            &["items".to_string()],
            PROOF,
        );
        assert_eq!(query.statements.len(), 5);
        assert!(query.sql.split(';').all(|statement| {
            statement.trim().is_empty() || statement.trim_start().starts_with("SELECT ")
        }));
        assert!(!query.sql.contains("INSERT"));
        assert!(!query.sql.contains("UPDATE"));
        assert!(!query.sql.contains("DELETE"));
    }

    #[test]
    fn malformed_partial_and_fk_violation_batches_fail_closed() {
        let manifest = manifest("CREATE TABLE items(id INTEGER PRIMARY KEY);");
        let query = build_fixed_query("d1_migrations", 1, &[], &[], PROOF);
        assert!(parse_complete_batch(&json!([]), &query.statements, PROOF, &manifest).is_err());
        let table_query = build_fixed_query(
            "d1_migrations",
            1,
            &["items".to_string()],
            &["items".to_string()],
            PROOF,
        );
        let mut result_sets = table_query
            .statements
            .iter()
            .map(|statement| tagged_result(statement, PROOF, Vec::new(), None))
            .collect::<Vec<_>>();
        result_sets[4] = tagged_result(
            &table_query.statements[4],
            PROOF,
            vec![json!({"table":"items","rowid":1,"parent":"parents","fkid":0})],
            None,
        );
        assert!(
            parse_complete_batch(
                &json!(result_sets),
                &table_query.statements,
                PROOF,
                &manifest
            )
            .is_err()
        );
    }

    #[test]
    fn statement_markers_and_read_only_metadata_are_exact() {
        let statement = BatchStatement::Ledger;
        let mut wrong_marker = tagged_result(&statement, PROOF, Vec::new(), None);
        wrong_marker["results"][0]["__cf_mcp_statement_id"] = json!("b".repeat(64));
        assert!(result_rows(&wrong_marker, &statement, PROOF).is_err());

        for meta in [
            json!({"changed_db": "false"}),
            json!({"changes": "0"}),
            json!({"rows_written": 0.0}),
            json!({"changed_db": true}),
            json!({"changes": 1}),
        ] {
            let malformed = tagged_result(&statement, PROOF, Vec::new(), Some(meta));
            assert!(result_rows(&malformed, &statement, PROOF).is_err());
        }
        let valid = tagged_result(
            &statement,
            PROOF,
            Vec::new(),
            Some(json!({"changed_db": false, "changes": 0, "rows_written": 0})),
        );
        assert!(result_rows(&valid, &statement, PROOF).is_ok());

        let mut missing_meta = valid.clone();
        missing_meta
            .as_object_mut()
            .expect("result object")
            .remove("meta");
        let mut non_object_meta = valid.clone();
        non_object_meta["meta"] = Value::Null;
        let mut missing_primary = valid.clone();
        missing_primary["meta"]
            .as_object_mut()
            .expect("metadata object")
            .remove("served_by_primary");
        let mut false_primary = valid.clone();
        false_primary["meta"]["served_by_primary"] = json!(false);
        let mut null_primary = valid.clone();
        null_primary["meta"]["served_by_primary"] = Value::Null;
        let mut wrong_type_primary = valid.clone();
        wrong_type_primary["meta"]["served_by_primary"] = json!("true");
        for candidate in [
            missing_meta,
            non_object_meta,
            missing_primary,
            false_primary,
            null_primary,
            wrong_type_primary,
        ] {
            let error = result_rows(&candidate, &statement, PROOF)
                .expect_err("primary-current evidence must be exact");
            let content = error.structured_content.expect("structured primary error");
            assert_eq!(
                content["error"]["code"],
                "d1.migration_reconciliation_primary_evidence_contradictory"
            );
        }
    }

    #[test]
    fn complete_batch_requires_primary_evidence_for_every_fixed_result_set() {
        let manifest = manifest("CREATE TABLE items(id INTEGER PRIMARY KEY);");
        let query = build_fixed_query("d1_migrations", 1, &[], &[], PROOF);
        let valid_result_sets = query
            .statements
            .iter()
            .map(|statement| tagged_result(statement, PROOF, Vec::new(), None))
            .collect::<Vec<_>>();
        for index in 0..valid_result_sets.len() {
            let mut mixed = valid_result_sets.clone();
            mixed[index]["meta"]["served_by_primary"] = json!(false);
            let error =
                parse_complete_batch(&Value::Array(mixed), &query.statements, PROOF, &manifest)
                    .expect_err("one non-primary result set must fail the complete batch");
            let content = error.structured_content.expect("structured primary error");
            assert_eq!(
                content["error"]["code"],
                "d1.migration_reconciliation_primary_evidence_contradictory",
                "result set {index}"
            );
        }
    }

    #[test]
    fn lease_revalidation_drift_remains_unverified_after_outer_context() {
        let response_evidence = json!([
            {
                "response_body_sha256": PROOF,
                "response_body_size_bytes": 101,
                "lifecycle": {
                    "dispatch_stage": "attempted",
                    "response_stage": "received",
                    "body_stage": "completely_read",
                    "http_status": 200,
                },
            },
            {
                "response_body_sha256": SECOND_PROOF,
                "response_body_size_bytes": 102,
                "lifecycle": {
                    "dispatch_stage": "attempted",
                    "response_stage": "received",
                    "body_stage": "completely_read",
                    "http_status": 200,
                },
            },
        ]);
        let wrapped = contextualize_unverified_custody_error(
            reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_lease_changed",
                "retained evidence changed",
            ),
            Some(PROOF),
            response_evidence.as_array().expect("response evidence"),
            2,
        );
        let content = wrapped.structured_content.expect("structured drift");
        assert_eq!(content["lease_decision"], "retain");
        assert_eq!(content["lease_retained"], Value::Null);
        assert_eq!(content["custody_status"], "retained_evidence_unverified");
        assert_eq!(content["provider_calls"], 2);
        assert_eq!(content["response_evidence"], response_evidence);
        assert_eq!(
            content["provider_read_lifecycle"],
            json!([
                {
                    "dispatch_stage": "attempted",
                    "response_stage": "received",
                    "body_stage": "completely_read",
                    "http_status": 200,
                },
                {
                    "dispatch_stage": "attempted",
                    "response_stage": "received",
                    "body_stage": "completely_read",
                    "http_status": 200,
                },
            ])
        );
    }

    #[test]
    fn provider_error_preserves_classification_when_custody_revalidation_fails() {
        let provider_error = adapter_batch_error(
            D1MigrationReconciliationBatchError {
                error: crate::cloudflare::client::AdapterErrorPayload {
                    code: "cloudflare.http_server_error",
                    message: "synthetic provider failure".to_string(),
                    hint: "synthetic fixture",
                    retryable: false,
                    status: Some(503),
                    classification: None,
                },
                response_body_sha256: Some(PROOF.to_string()),
                response_body_size_bytes: Some(31),
                lifecycle: D1MigrationReconciliationReadLifecycle {
                    dispatch_stage: "attempted",
                    response_stage: "received",
                    body_stage: "completely_read",
                    http_status: Some(503),
                },
            },
            PROOF,
        );
        let result = contextualize_provider_error_with_unverified_custody(
            provider_error,
            reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_lease_changed",
                "retained evidence changed during the provider call",
            ),
            Some(PROOF),
            1,
        );
        let content = result
            .structured_content
            .expect("structured provider error");
        assert_eq!(content["capability_state"], "unavailable");
        assert_eq!(
            content["error"]["code"],
            "d1.migration_reconciliation_provider_unavailable"
        );
        assert_eq!(content["provider_cause"]["status"], 503);
        assert_eq!(
            content["custody_cause"]["code"],
            "d1.migration_reconciliation_lease_changed"
        );
        assert_eq!(content["lease_retained"], Value::Null);
        assert_eq!(content["custody_status"], "retained_evidence_unverified");
        assert_eq!(content["provider_calls"], 1);
        assert_eq!(
            content["response_evidence"].as_array().map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn outer_context_prepends_prior_response_evidence_without_losing_inner_evidence() {
        let first = json!({
            "response_body_sha256": "first",
            "lifecycle": {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            },
        });
        let second_evidence = json!({
            "response_body_sha256": "second",
            "lifecycle": {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 503,
            },
        });
        let second = contextualize_error(
            reconciliation_error_with_evidence(
                "unavailable",
                "d1.migration_reconciliation_provider_unavailable",
                "second provider call failed",
                Some(PROOF),
                &[second_evidence.clone()],
            ),
            Some(PROOF),
            &[],
            1,
        );
        let merged = contextualize_error(second, Some(PROOF), &[first.clone()], 1);
        let content = merged.structured_content.expect("merged response evidence");
        assert_eq!(
            content["response_evidence"],
            json!([first, second_evidence])
        );
        assert_eq!(content["provider_calls"], 2);
        assert_eq!(
            content["provider_read_lifecycle"],
            json!([
                {
                    "dispatch_stage": "attempted",
                    "response_stage": "received",
                    "body_stage": "completely_read",
                    "http_status": 200,
                },
                {
                    "dispatch_stage": "attempted",
                    "response_stage": "received",
                    "body_stage": "completely_read",
                    "http_status": 503,
                },
            ])
        );
    }

    #[test]
    fn identical_successful_responses_remain_two_invocations_after_second_custody_drift() {
        let response = json!({
            "response_body_sha256": PROOF,
            "response_body_size_bytes": 101,
            "lifecycle": {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            },
        });
        let inner = contextualize_unverified_custody_error(
            reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_lease_changed",
                "retained evidence changed after the second provider call",
            ),
            Some(PROOF),
            &[response.clone()],
            1,
        );
        let result = contextualize_error(inner, Some(PROOF), &[response.clone()], 1);
        let content = result.structured_content.expect("structured custody drift");
        assert_eq!(
            content,
            json!({
                "ok": false,
                "operation": "d1_reconcile_migration_manifest",
                "dry_run": true,
                "read_only": true,
                "status": "reconciliation_required",
                "outcome": "unknown",
                "capability_state": "contradictory",
                "retry_decision": "do_not_retry_same_attempt",
                "lease_decision": "retain",
                "lease_retained": null,
                "custody_status": "retained_evidence_unverified",
                "query_sha256": PROOF,
                "response_evidence": [response.clone(), response.clone()],
                "provider_read_lifecycle": [
                    response["lifecycle"].clone(),
                    response["lifecycle"].clone(),
                ],
                "provider_calls": 2,
                "provider_mutations": 0,
                "local_namespace_mutations": 0,
                "error": {
                    "code": "d1.migration_reconciliation_lease_changed",
                    "message": "retained evidence changed after the second provider call",
                    "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result.",
                },
            })
        );

        let replayed = contextualize_error(
            CallToolResult::structured_error(content.clone()),
            Some(PROOF),
            &[response],
            1,
        );
        assert_eq!(
            replayed.structured_content.expect("replayed product"),
            content,
            "reprocessing an already merged product must remain idempotent",
        );
    }

    #[test]
    fn second_call_without_response_preserves_chronological_invocation_evidence() {
        let first = json!({
            "response_body_sha256": PROOF,
            "response_body_size_bytes": 101,
            "lifecycle": {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            },
        });
        let first_lifecycle = first["lifecycle"].clone();

        for (pre_dispatch, custody_verified) in
            [(false, true), (false, false), (true, true), (true, false)]
        {
            let second_lifecycle = if pre_dispatch {
                D1MigrationReconciliationReadLifecycle {
                    dispatch_stage: "pre_dispatch",
                    response_stage: "not_received",
                    body_stage: "not_read",
                    http_status: None,
                }
            } else {
                D1MigrationReconciliationReadLifecycle {
                    dispatch_stage: "attempted",
                    response_stage: "not_received",
                    body_stage: "not_read",
                    http_status: None,
                }
            };
            let provider_code = if pre_dispatch {
                "cloudflare.config_missing_token"
            } else {
                "cloudflare.transport_error"
            };
            let capability_state = if pre_dispatch {
                "capability_gap"
            } else {
                "unavailable"
            };
            let error_code = if pre_dispatch {
                "d1.migration_reconciliation_query_capability_gap"
            } else {
                "d1.migration_reconciliation_provider_unavailable"
            };
            let second = adapter_batch_error(
                D1MigrationReconciliationBatchError {
                    error: crate::cloudflare::client::AdapterErrorPayload {
                        code: provider_code,
                        message: "synthetic second-call failure".to_string(),
                        hint: "synthetic fixture",
                        retryable: false,
                        status: None,
                        classification: None,
                    },
                    response_body_sha256: None,
                    response_body_size_bytes: None,
                    lifecycle: second_lifecycle,
                },
                PROOF,
            );
            let second = if custody_verified {
                contextualize_error(second, Some(PROOF), &[], 0)
            } else {
                contextualize_provider_error_with_unverified_custody(
                    second,
                    reconciliation_error(
                        "contradictory",
                        "d1.migration_reconciliation_lease_changed",
                        "retained evidence changed during the second provider call",
                    ),
                    Some(PROOF),
                    second_lifecycle.provider_calls(),
                )
            };
            let result = contextualize_error(second, Some(PROOF), &[first.clone()], 1);
            let content = result
                .structured_content
                .expect("structured second-call failure");
            let mut expected = json!({
                "ok": false,
                "operation": "d1_reconcile_migration_manifest",
                "dry_run": true,
                "read_only": true,
                "status": "reconciliation_required",
                "outcome": "unknown",
                "capability_state": capability_state,
                "retry_decision": "do_not_retry_same_attempt",
                "lease_decision": "retain",
                "lease_retained": custody_verified.then_some(true),
                "custody_status": if custody_verified {
                    "retained_evidence_verified"
                } else {
                    "retained_evidence_unverified"
                },
                "query_sha256": PROOF,
                "response_evidence": [first.clone()],
                "provider_read_lifecycle": [first_lifecycle.clone(), second_lifecycle],
                "provider_calls": if pre_dispatch { 1 } else { 2 },
                "provider_mutations": 0,
                "local_namespace_mutations": 0,
                "provider_cause": {
                    "code": provider_code,
                    "status": null,
                    "retryable": false,
                    "operator_guidance": "reconciliation_only",
                },
                "error": {
                    "code": error_code,
                    "message": "provider could not return one complete strict read-only reconciliation batch",
                    "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result.",
                },
            });
            if !custody_verified {
                expected.as_object_mut().expect("expected object").insert(
                    "custody_cause".to_string(),
                    json!({
                        "code": "d1.migration_reconciliation_lease_changed",
                        "message": "retained evidence changed during the second provider call",
                        "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result.",
                    }),
                );
            }
            assert_eq!(
                content, expected,
                "pre_dispatch={pre_dispatch} custody_verified={custody_verified}"
            );
        }
    }

    #[test]
    fn existing_merged_lifecycle_and_body_evidence_are_not_duplicated() {
        let first = json!({
            "response_body_sha256": PROOF,
            "response_body_size_bytes": 101,
            "lifecycle": {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            },
        });
        let second_lifecycle = json!({
            "dispatch_stage": "pre_dispatch",
            "response_stage": "not_received",
            "body_stage": "not_read",
            "http_status": null,
        });
        let mut content = json!({
            "response_evidence": [first.clone()],
            "provider_read_lifecycle": [first["lifecycle"].clone(), second_lifecycle.clone()],
            "provider_calls": 1,
        })
        .as_object()
        .expect("content object")
        .clone();
        let already_contains_prior =
            product_already_contains_prior_invocations(&content, &[first.clone()], 1);
        assert_eq!(
            merge_provider_lifecycle_with_response_evidence(
                &content,
                &[first.clone()],
                already_contains_prior,
            ),
            json!([first["lifecycle"].clone(), second_lifecycle])
                .as_array()
                .expect("expected lifecycle")
                .clone(),
        );
        prepend_response_evidence(&mut content, &[first.clone()], already_contains_prior);
        assert_eq!(content["response_evidence"], json!([first]));

        let retained_lifecycle = content["response_evidence"][0]["lifecycle"].clone();
        content.insert(
            "provider_read_lifecycle".to_string(),
            json!([
                retained_lifecycle.clone(),
                {
                    "dispatch_stage": "attempted",
                    "response_stage": "received",
                    "body_stage": "completely_read",
                    "http_status": 200,
                },
            ]),
        );
        assert_eq!(
            merge_provider_lifecycle_with_response_evidence(
                &content,
                content["response_evidence"]
                    .as_array()
                    .expect("prior response evidence"),
                true,
            ),
            json!([retained_lifecycle])
                .as_array()
                .expect("stale-free lifecycle")
                .clone(),
        );
    }

    #[test]
    fn post_read_contradictions_retain_verified_custody_context() {
        let first = json!({
            "response_body_sha256": PROOF,
            "response_body_size_bytes": 101,
            "lifecycle": {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            },
        });
        let second = json!({
            "response_body_sha256": SECOND_PROOF,
            "response_body_size_bytes": 102,
            "lifecycle": {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            },
        });
        let result = contextualize_error(
            reconciliation_error_with_evidence(
                "contradictory",
                "d1.migration_reconciliation_evidence_unstable",
                "stable reads differed",
                Some(PROOF),
                &[first.clone(), second.clone()],
            ),
            Some(PROOF),
            &[],
            2,
        );
        let content = result.structured_content.expect("structured contradiction");
        assert_eq!(
            content,
            json!({
                "ok": false,
                "operation": "d1_reconcile_migration_manifest",
                "dry_run": true,
                "read_only": true,
                "status": "reconciliation_required",
                "outcome": "unknown",
                "capability_state": "contradictory",
                "retry_decision": "do_not_retry_same_attempt",
                "lease_decision": "retain",
                "lease_retained": true,
                "custody_status": "retained_evidence_verified",
                "query_sha256": PROOF,
                "response_evidence": [first, second],
                "provider_read_lifecycle": [
                    {
                        "dispatch_stage": "attempted",
                        "response_stage": "received",
                        "body_stage": "completely_read",
                        "http_status": 200,
                    },
                    {
                        "dispatch_stage": "attempted",
                        "response_stage": "received",
                        "body_stage": "completely_read",
                        "http_status": 200,
                    },
                ],
                "provider_calls": 2,
                "provider_mutations": 0,
                "local_namespace_mutations": 0,
                "error": {
                    "code": "d1.migration_reconciliation_evidence_unstable",
                    "message": "stable reads differed",
                    "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result.",
                },
            })
        );
    }

    #[test]
    fn rate_limit_and_server_statuses_are_unavailable_without_retry() {
        for status in [401, 403, 429, 500, 503, 599] {
            let result = adapter_batch_error(
                D1MigrationReconciliationBatchError {
                    error: crate::cloudflare::client::AdapterErrorPayload {
                        code: "cloudflare.http_error",
                        message: format!("HTTP status {status}"),
                        hint: "synthetic fixture",
                        retryable: true,
                        status: Some(status),
                        classification: None,
                    },
                    response_body_sha256: Some(PROOF.to_string()),
                    response_body_size_bytes: Some(2),
                    lifecycle: D1MigrationReconciliationReadLifecycle {
                        dispatch_stage: "attempted",
                        response_stage: "received",
                        body_stage: "completely_read",
                        http_status: Some(status),
                    },
                },
                PROOF,
            );
            let content = result.structured_content.expect("structured status");
            assert_eq!(content["capability_state"], "unavailable", "{status}");
            assert_eq!(
                content["error"]["code"], "d1.migration_reconciliation_provider_unavailable",
                "{status}"
            );
            assert_eq!(content["retry_decision"], "do_not_retry_same_attempt");
            assert_eq!(content["provider_cause"]["retryable"], false);
            assert_eq!(content["provider_calls"], 1);
            assert_eq!(
                content["provider_read_lifecycle"],
                json!([{
                    "dispatch_stage": "attempted",
                    "response_stage": "received",
                    "body_stage": "completely_read",
                    "http_status": status,
                }])
            );
        }
    }

    #[test]
    fn schema_and_xinfo_mismatch_are_contradictory() {
        let expected = D1MigrationStateExpectation {
            manifest_prefix_length: 1,
            schema_objects: vec![D1MigrationSchemaObjectExpectation {
                object_type: "table".to_string(),
                name: "items".to_string(),
                table_name: "items".to_string(),
                sql_sha256: "a".repeat(64),
            }],
            tables: vec![D1MigrationTableExpectation {
                name: "items".to_string(),
                columns: vec![D1MigrationColumnExpectation {
                    cid: 0,
                    name: "id".to_string(),
                    declared_type: "INTEGER".to_string(),
                    not_null: false,
                    default_value: None,
                    primary_key_position: 1,
                    hidden: 0,
                }],
                foreign_keys: Vec::new(),
            }],
        };
        let derived = vec![
            Vec::new(),
            vec![DerivedSchemaObject {
                object_type: "table".to_string(),
                name: "items".to_string(),
                table_name: "items".to_string(),
            }],
        ];
        let validated = validate_expectations(&derived, vec![empty_state(), expected.clone()])
            .expect("expectations");
        let snapshot = CanonicalSnapshot {
            ledger: vec![D1ManifestLedgerRow {
                id: 1,
                name: "0001_create.sql".to_string(),
            }],
            schema_objects: Vec::new(),
            tables: vec![ObservedTable {
                name: "items".to_string(),
                columns: Vec::new(),
                foreign_keys: Vec::new(),
            }],
        };
        assert!(verify_expected_state(&expected, &validated, &snapshot).is_err());
    }
}
