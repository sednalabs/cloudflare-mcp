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
};
use crate::d1_migration_lease::{D1RetainedMigrationLease, inspect_retained_d1_migration_lease};
use crate::d1_migration_manifest::{
    D1ManifestLedgerRow, classify_d1_manifest_ledger, d1_ledger_summaries, d1_manifest_plan_sha256,
    d1_manifest_summaries,
};
use crate::server::CloudflareMcp;
use crate::tools::{D1MigrationManifestEntry, sha256_bytes_hex};

const OPERATION: &str = "d1_reconcile_migration_manifest";
const EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1: &str = "schema_create_only_v1";
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
    let derived_states = match derive_effect_assertion(effect_assertion_id, manifest) {
        Ok(derived_states) => derived_states,
        Err(result) => return prelease_error(result, "not_inspected", None),
    };
    let validated = match validate_expectations(&derived_states, state_expectations) {
        Ok(validated) => validated,
        Err(result) => return prelease_error(result, "not_inspected", None),
    };
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
        Err(result) => return prelease_error(result, "inspection_failed", Some(&query.sha256)),
    };

    let first = match read_complete_batch(server, &lease, account_id, database_id, &query, manifest)
        .await
    {
        Ok(batch) => batch,
        Err(result) => return result,
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
            return contextualize_error(
                result,
                Some(&query.sha256),
                &[response_digest_summary(&first)],
                1,
            );
        }
    };
    if let Err(result) = lease.revalidate() {
        return contextualize_unverified_custody_error(
            result,
            Some(&query.sha256),
            &[
                response_digest_summary(&first),
                response_digest_summary(&second),
            ],
            2,
        );
    }
    let second_digest = batch_digest(&second);
    if first.snapshot != second.snapshot || first_digest != second_digest {
        return contextualize_error(
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
        );
    }

    let ledger_classification = match classify_d1_manifest_ledger(manifest, &first.snapshot.ledger)
    {
        Ok(classification) => classification,
        Err(_) => {
            return contextualize_error(
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
            );
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
            return contextualize_error(
                result,
                Some(&query.sha256),
                &[
                    response_digest_summary(&first),
                    response_digest_summary(&second),
                ],
                2,
            );
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
            return contextualize_error(
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
            );
        }
    };
    if let Err(result) = verify_expected_state(expected_state, &validated, &first.snapshot) {
        return contextualize_error(
            result,
            Some(&query.sha256),
            &[
                response_digest_summary(&first),
                response_digest_summary(&second),
            ],
            2,
        );
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
        return contextualize_error(
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
        );
    }

    let snapshot_sha256 = first_digest;
    let reconciliation_plan_sha256 = reconciliation_plan_sha256(
        account_id,
        database_id,
        family,
        migrations_table,
        manifest,
        &lease,
        original_prefix,
        current_prefix,
        outcome,
        &query.sha256,
        &snapshot_sha256,
    );
    CallToolResult::structured(json!({
        "ok": true,
        "operation": OPERATION,
        "dry_run": true,
        "read_only": true,
        "status": "reconciliation_evidence_ready",
        "outcome": outcome,
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
        "reconstructed_original_prefix_length": original_prefix,
        "current_manifest_prefix_length": current_prefix,
        "ledger": d1_ledger_summaries(&first.snapshot.ledger),
        "lease": lease.identity,
        "query_sha256": query.sha256,
        "expectation_proof_sha256": validated.proof_sha256,
        "query_sha256s": [&query.sha256, &query.sha256],
        "response_evidence": [response_digest_summary(&first), response_digest_summary(&second)],
        "canonical_snapshot_sha256": snapshot_sha256,
        "scope_completeness": {
            "ledger": "complete_bounded_manifest_prefix",
            "sqlite_master": "complete_exact_declared_object_union",
            "table_xinfo": "complete_exact_declared_table_union",
            "foreign_key_list": "complete_exact_declared_table_union",
            "foreign_key_check": "bounded_zero_violation_proof_for_every_declared_table",
            "migration_effects": EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1,
        },
        "effect_assertion": {
            "id": EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1,
            "source": "built_in_registry_and_exact_manifest_sql_classification",
            "caller_schema_only_declaration_used": false,
        },
        "reconciliation_plan_sha256": reconciliation_plan_sha256,
        "future_live_transition": "not_implemented_in_this_slice",
        "provider_calls": 2,
        "provider_mutations": 0,
        "local_namespace_mutations": 0,
    }))
}

#[derive(Debug)]
struct ParsedBatch {
    snapshot: CanonicalSnapshot,
    response_body_sha256: String,
    response_body_size_bytes: usize,
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
            let provider_error = adapter_batch_error(error, &query.sha256);
            return Err(match lease.revalidate() {
                Ok(()) => contextualize_error(provider_error, Some(&query.sha256), &[], 1),
                Err(custody_error) => contextualize_provider_error_with_unverified_custody(
                    provider_error,
                    custody_error,
                    Some(&query.sha256),
                    1,
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
            if !matches!(object.object_type.as_str(), "table" | "index")
                || !valid_sha256(&object.sql_sha256)
            {
                return Err(reconciliation_error(
                    "capability_gap",
                    "d1.migration_reconciliation_schema_expectation_invalid",
                    "schema objects must be table/index entries with lowercase exact SQL SHA-256 digests",
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
enum SqlToken {
    Word(String),
    Identifier(String),
    StringLiteral,
    Symbol(char),
}

fn derive_effect_assertion(
    effect_assertion_id: Option<&str>,
    manifest: &[D1MigrationManifestEntry],
) -> Result<Vec<Vec<DerivedSchemaObject>>, CallToolResult> {
    if effect_assertion_id != Some(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1) {
        return Err(reconciliation_error(
            "capability_gap",
            "d1.migration_reconciliation_effect_assertion_missing",
            "a supported registry-backed migration effect assertion is required",
        ));
    }
    let mut cumulative = BTreeMap::<(String, String), DerivedSchemaObject>::new();
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
            let object = schema_create_only(&tokens).ok_or_else(|| {
                reconciliation_error(
                    "capability_gap",
                    "d1.migration_reconciliation_effect_proof_unavailable",
                    "the built-in effect registry cannot exactly prove arbitrary DML, ALTER, DROP, PRAGMA, trigger, view, virtual table, or data-producing CREATE effects",
                )
            })?;
            let key = (object.object_type.clone(), object.name.clone());
            if cumulative.insert(key, object).is_some() {
                return Err(reconciliation_error(
                    "contradictory",
                    "d1.migration_reconciliation_create_target_reused",
                    "the manifest reuses a CREATE object identity and cannot derive one exact schema state per prefix",
                ));
            }
        }
        states.push(cumulative.values().cloned().collect());
    }
    Ok(states)
}

fn schema_create_only(tokens: &[SqlToken]) -> Option<DerivedSchemaObject> {
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
    } else {
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
    }
}

fn token_is_word(token: Option<&SqlToken>, value: &str) -> bool {
    matches!(token, Some(SqlToken::Word(word)) if word.eq_ignore_ascii_case(value))
}

fn token_identifier(token: Option<&SqlToken>) -> Option<String> {
    match token? {
        SqlToken::Word(value) | SqlToken::Identifier(value) => Some(value.clone()),
        SqlToken::StringLiteral | SqlToken::Symbol(_) => None,
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
    let mut statements = Vec::new();
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
                    if !tokens.is_empty() {
                        statements.push(std::mem::take(&mut tokens));
                    }
                }
                (b'(' | b')' | b',', _) => {
                    flush_token(&mut token, &mut tokens);
                    tokens.push(SqlToken::Symbol(byte as char));
                }
                _ if byte.is_ascii_alphanumeric() || byte == b'_' => token.push(byte),
                _ => flush_token(&mut token, &mut tokens),
            },
            Mode::SingleQuote => {
                if byte == b'\'' {
                    if next == Some(b'\'') {
                        index += 1;
                    } else {
                        mode = Mode::Normal;
                        tokens.push(SqlToken::StringLiteral);
                    }
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
    if !tokens.is_empty() {
        statements.push(tokens);
    }
    Some(statements)
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
        if !matches!(object_type.as_str(), "table" | "index")
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
    })
}

fn response_digest_summary_from_adapter(batch: &D1MigrationReconciliationBatch) -> Value {
    json!({
        "response_body_sha256": batch.response_body_sha256,
        "response_body_size_bytes": batch.response_body_size_bytes,
    })
}

fn adapter_batch_error(
    failure: D1MigrationReconciliationBatchError,
    query_sha256: &str,
) -> CallToolResult {
    let capability_state =
        if failure.error.status.is_some_and(|status| {
            matches!(status, 401 | 403 | 429) || (500..=599).contains(&status)
        }) || matches!(
            failure.error.code,
            "cloudflare.timeout" | "cloudflare.transport_error" | "cloudflare.response_read_failed"
        ) {
            "unavailable"
        } else if failure.error.message.contains("pragma_")
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
        })],
        (None, Some(size)) => vec![json!({
            "response_body_sha256": null,
            "response_body_size_bytes": size,
            "complete_body_digest": false,
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
    lease: &D1RetainedMigrationLease,
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
        "lease": lease.identity,
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
            .expect("reconciliation transition plan serialization is infallible"),
    )
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
        prepend_response_evidence(content, response_evidence);
        content.insert("provider_mutations".to_string(), json!(0));
        content.insert("local_namespace_mutations".to_string(), json!(0));
        let provider_calls = content
            .get("provider_calls")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .saturating_add(prior_provider_calls as u64);
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
        prepend_response_evidence(content, response_evidence);
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

fn prepend_response_evidence(content: &mut serde_json::Map<String, Value>, prior: &[Value]) {
    if prior.is_empty() {
        content
            .entry("response_evidence".to_string())
            .or_insert_with(|| json!([]));
        return;
    }
    let mut merged = prior.to_vec();
    if let Some(Value::Array(current)) = content.get("response_evidence") {
        merged.extend(current.iter().cloned());
    }
    content.insert("response_evidence".to_string(), Value::Array(merged));
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
        let drift = contextualize_unverified_custody_error(
            reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_lease_changed",
                "retained evidence changed",
            ),
            Some(PROOF),
            &[json!({"response_body_sha256": PROOF})],
            1,
        );
        let wrapped = contextualize_error(drift, Some(PROOF), &[], 1);
        let content = wrapped.structured_content.expect("structured drift");
        assert_eq!(content["lease_decision"], "retain");
        assert_eq!(content["lease_retained"], Value::Null);
        assert_eq!(content["custody_status"], "retained_evidence_unverified");
        assert_eq!(content["provider_calls"], 2);
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
        let second = contextualize_error(
            reconciliation_error_with_evidence(
                "unavailable",
                "d1.migration_reconciliation_provider_unavailable",
                "second provider call failed",
                Some(PROOF),
                &[json!({"response_body_sha256": "second"})],
            ),
            Some(PROOF),
            &[],
            1,
        );
        let merged = contextualize_error(
            second,
            Some(PROOF),
            &[json!({"response_body_sha256": "first"})],
            1,
        );
        let content = merged.structured_content.expect("merged response evidence");
        assert_eq!(
            content["response_evidence"],
            json!([
                {"response_body_sha256": "first"},
                {"response_body_sha256": "second"},
            ])
        );
        assert_eq!(content["provider_calls"], 2);
    }

    #[test]
    fn post_read_contradictions_retain_verified_custody_context() {
        let result = contextualize_error(
            reconciliation_error_with_evidence(
                "contradictory",
                "d1.migration_reconciliation_evidence_unstable",
                "stable reads differed",
                Some(PROOF),
                &[json!({"response_body_sha256": PROOF})],
            ),
            Some(PROOF),
            &[],
            2,
        );
        let content = result.structured_content.expect("structured contradiction");
        assert_eq!(content["lease_decision"], "retain");
        assert_eq!(content["lease_retained"], true);
        assert_eq!(content["custody_status"], "retained_evidence_verified");
        assert_eq!(content["provider_calls"], 2);
    }

    #[test]
    fn rate_limit_and_server_statuses_are_unavailable_without_retry() {
        for status in [429, 500, 503, 599] {
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
