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

#[derive(Debug)]
struct FixedQuery {
    sql: String,
    sha256: String,
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
    let validated = match validate_expectations(manifest.len(), state_expectations) {
        Ok(validated) => validated,
        Err(result) => return result,
    };
    if let Err(result) = validate_effect_assertion(effect_assertion_id, manifest) {
        return result;
    }
    let query = build_fixed_query(
        migrations_table,
        manifest.len(),
        &validated.object_names,
        &validated.table_names,
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
        Err(result) => return contextualize_error(result, Some(&query.sha256), &[]),
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
            );
        }
    };
    if let Err(result) = lease.revalidate() {
        return contextualize_error(
            result,
            Some(&query.sha256),
            &[
                response_digest_summary(&first),
                response_digest_summary(&second),
            ],
        );
    }
    let second_digest = batch_digest(&second);
    if first.snapshot != second.snapshot || first_digest != second_digest {
        return reconciliation_error_with_evidence(
            "contradictory",
            "d1.migration_reconciliation_evidence_unstable",
            "two complete read-only reconciliation batches were not canonically equivalent",
            Some(&query.sha256),
            &[
                response_digest_summary(&first),
                response_digest_summary(&second),
            ],
        );
    }

    let ledger_classification = match classify_d1_manifest_ledger(manifest, &first.snapshot.ledger)
    {
        Ok(classification) => classification,
        Err(_) => {
            return reconciliation_error_with_evidence(
                "contradictory",
                "d1.migration_reconciliation_ledger_not_manifest_prefix",
                "stable migration ledger is not an exact prefix of the supplied manifest",
                Some(&query.sha256),
                &[
                    response_digest_summary(&first),
                    response_digest_summary(&second),
                ],
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
            return reconciliation_error_with_evidence(
                "capability_gap",
                "d1.migration_reconciliation_state_expectation_missing",
                "no bounded reviewed state expectation covers the stable current manifest prefix",
                Some(&query.sha256),
                &[
                    response_digest_summary(&first),
                    response_digest_summary(&second),
                ],
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
        return reconciliation_error_with_evidence(
            "contradictory",
            "d1.migration_reconciliation_plan_relationship_contradictory",
            "stable ledger precedes the uniquely reconstructed approved-plan prefix",
            Some(&query.sha256),
            &[
                response_digest_summary(&first),
                response_digest_summary(&second),
            ],
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
    lease
        .revalidate()
        .map_err(|result| contextualize_error(result, Some(&query.sha256), &[]))?;
    let batch = server
        .cloudflare
        .query_d1_migration_reconciliation_batch(account_id, database_id, &query.sql)
        .await
        .map_err(|error| adapter_batch_error(error, &query.sha256))?;
    lease.revalidate().map_err(|result| {
        contextualize_error(
            result,
            Some(&query.sha256),
            &[response_digest_summary_from_adapter(&batch)],
        )
    })?;
    let snapshot =
        parse_complete_batch(&batch.result, &query.statements, manifest).map_err(|result| {
            contextualize_error(
                result,
                Some(&query.sha256),
                &[response_digest_summary_from_adapter(&batch)],
            )
        })?;
    Ok(ParsedBatch {
        snapshot,
        response_body_sha256: batch.response_body_sha256,
        response_body_size_bytes: batch.response_body_size_bytes,
    })
}

fn validate_expectations(
    manifest_len: usize,
    states: Vec<D1MigrationStateExpectation>,
) -> Result<ValidatedExpectations, CallToolResult> {
    if states.is_empty() || states.len() > MAX_STATE_EXPECTATIONS {
        return Err(reconciliation_error(
            "capability_gap",
            "d1.migration_reconciliation_expectations_unbounded",
            "state_expectations must contain 1..128 reviewed manifest-prefix states",
        ));
    }
    let mut previous_prefix = None;
    let mut object_names = BTreeSet::new();
    let mut table_names = BTreeSet::new();
    for state in &states {
        if state.manifest_prefix_length > manifest_len
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
            object_names.insert(object.name.clone());
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
    Ok(ValidatedExpectations {
        states,
        object_names: object_names.into_iter().collect(),
        table_names: table_names.into_iter().collect(),
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

fn validate_effect_assertion(
    effect_assertion_id: Option<&str>,
    manifest: &[D1MigrationManifestEntry],
) -> Result<(), CallToolResult> {
    if effect_assertion_id != Some(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1) {
        return Err(reconciliation_error(
            "capability_gap",
            "d1.migration_reconciliation_effect_assertion_missing",
            "a supported registry-backed migration effect assertion is required",
        ));
    }
    for migration in manifest {
        let statements = tokenize_sql_statements(&migration.sql).ok_or_else(|| {
            reconciliation_error(
                "capability_gap",
                "d1.migration_reconciliation_effect_proof_unavailable",
                "exact migration SQL could not be classified by the built-in effect registry",
            )
        })?;
        if statements.is_empty() || statements.iter().any(|tokens| !schema_create_only(tokens)) {
            return Err(reconciliation_error(
                "capability_gap",
                "d1.migration_reconciliation_effect_proof_unavailable",
                "the built-in effect registry cannot exactly prove arbitrary DML, ALTER, DROP, PRAGMA, trigger, view, or data-copy effects",
            ));
        }
    }
    Ok(())
}

fn schema_create_only(tokens: &[String]) -> bool {
    let allowed_prefix = tokens.starts_with(&["create".into(), "table".into()])
        || tokens.starts_with(&["create".into(), "index".into()])
        || tokens.starts_with(&["create".into(), "unique".into(), "index".into()]);
    allowed_prefix
        && !tokens.iter().any(|token| token == "select")
        && !tokens.iter().any(|token| token == "virtual")
}

fn tokenize_sql_statements(sql: &str) -> Option<Vec<Vec<String>>> {
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
    let mut index = 0;
    let flush_token = |token: &mut Vec<u8>, tokens: &mut Vec<String>| {
        if !token.is_empty() {
            tokens.push(String::from_utf8_lossy(token).to_ascii_lowercase());
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
                    mode = Mode::DoubleQuote;
                }
                (b'`', _) => {
                    flush_token(&mut token, &mut tokens);
                    mode = Mode::Backtick;
                }
                (b'[', _) => {
                    flush_token(&mut token, &mut tokens);
                    mode = Mode::Bracket;
                }
                (b';', _) => {
                    flush_token(&mut token, &mut tokens);
                    if !tokens.is_empty() {
                        statements.push(std::mem::take(&mut tokens));
                    }
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
                    }
                }
            }
            Mode::DoubleQuote => {
                if byte == b'"' {
                    if next == Some(b'"') {
                        index += 1;
                    } else {
                        mode = Mode::Normal;
                    }
                }
            }
            Mode::Backtick => {
                if byte == b'`' {
                    mode = Mode::Normal;
                }
            }
            Mode::Bracket => {
                if byte == b']' {
                    mode = Mode::Normal;
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
) -> FixedQuery {
    let mut sql = Vec::new();
    let mut statements = Vec::new();
    sql.push(format!(
        "SELECT id, name FROM {} ORDER BY id LIMIT {}",
        quote_identifier(migrations_table),
        manifest_len + 1
    ));
    statements.push(BatchStatement::Ledger);
    let names = if object_names.is_empty() {
        String::from("NULL")
    } else {
        object_names
            .iter()
            .map(|name| quote_string(name))
            .collect::<Vec<_>>()
            .join(", ")
    };
    sql.push(format!(
        "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name IN ({names}) ORDER BY type, name LIMIT {}",
        object_names.len() + 1
    ));
    statements.push(BatchStatement::Schema);
    for table in table_names {
        let table_string = quote_string(table);
        sql.push(format!(
            "SELECT cid, name, type, \"notnull\", dflt_value, pk, hidden FROM pragma_table_xinfo({table_string}) ORDER BY cid LIMIT {}",
            MAX_COLUMNS_PER_TABLE + 1
        ));
        statements.push(BatchStatement::TableXinfo(table.clone()));
        sql.push(format!(
            "SELECT id, seq, \"table\", \"from\", \"to\", on_update, on_delete, \"match\" FROM pragma_foreign_key_list({table_string}) ORDER BY id, seq LIMIT {}",
            MAX_FOREIGN_KEYS_PER_TABLE + 1
        ));
        statements.push(BatchStatement::ForeignKeyList(table.clone()));
        sql.push(format!(
            "SELECT \"table\", rowid, parent, fkid FROM pragma_foreign_key_check({table_string}) LIMIT 1"
        ));
        statements.push(BatchStatement::ForeignKeyCheck(table.clone()));
    }
    let sql = sql.join(";\n");
    FixedQuery {
        sha256: sha256_bytes_hex(sql.as_bytes()),
        sql,
        statements,
    }
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
        let rows = result_rows(result_set)?;
        match statement {
            BatchStatement::Ledger => {
                if rows.len() > manifest.len() {
                    return Err(reconciliation_error(
                        "contradictory",
                        "d1.migration_reconciliation_ledger_unbounded",
                        "migration ledger exceeded the exact manifest prefix bound",
                    ));
                }
                ledger = Some(parse_ledger_rows(rows)?);
            }
            BatchStatement::Schema => {
                if rows.len() > MAX_SCHEMA_OBJECTS {
                    return Err(reconciliation_error(
                        "contradictory",
                        "d1.migration_reconciliation_schema_unbounded",
                        "sqlite_master evidence exceeded the declared object bound",
                    ));
                }
                schema_objects = Some(parse_schema_rows(rows)?);
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
                    .columns = parse_column_rows(rows)?;
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
                    .foreign_keys = parse_foreign_key_rows(rows)?;
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

fn result_rows(result_set: &Value) -> Result<&[Value], CallToolResult> {
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
    if let Some(meta) = object.get("meta") {
        let meta = meta.as_object().ok_or_else(|| {
            reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_meta_malformed",
                "provider result metadata was not an object",
            )
        })?;
        if meta
            .get("changed_db")
            .is_some_and(|value| value != &json!(false))
            || meta
                .get("changes")
                .and_then(Value::as_i64)
                .is_some_and(|value| value != 0)
            || meta
                .get("rows_written")
                .and_then(Value::as_i64)
                .is_some_and(|value| value != 0)
        {
            return Err(reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_read_only_meta_contradictory",
                "provider metadata contradicted the internally constructed read-only batch",
            ));
        }
    }
    object
        .get("results")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| {
            reconciliation_error(
                "contradictory",
                "d1.migration_reconciliation_rows_missing",
                "a reconciliation result set omitted its rows array",
            )
        })
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
    let capability_state = if failure
        .error
        .status
        .is_some_and(|status| matches!(status, 401 | 403))
        || matches!(
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
        })],
        _ => Vec::new(),
    };
    let mut result = reconciliation_error_with_evidence(
        capability_state,
        if capability_state == "capability_gap" {
            "d1.migration_reconciliation_query_capability_gap"
        } else {
            "d1.migration_reconciliation_provider_unavailable"
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
        content.insert("lease_decision".to_string(), json!("retain"));
        content.insert("lease_retained".to_string(), json!(true));
        content.insert("query_sha256".to_string(), json!(query_sha256));
        content.insert("response_evidence".to_string(), json!(response_evidence));
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
        "lease_decision": "retain",
        "lease_retained": true,
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

    fn manifest(sql: &str) -> Vec<D1MigrationManifestEntry> {
        vec![D1MigrationManifestEntry {
            name: "0001_create.sql".to_string(),
            size_bytes: sql.len() as u64,
            sql_sha256: sha256_bytes_hex(sql.as_bytes()),
            sql: sql.to_string(),
        }]
    }

    #[test]
    fn registry_rejects_missing_and_non_schema_effect_proof() {
        let create = manifest("CREATE TABLE items(id INTEGER PRIMARY KEY);");
        assert!(validate_effect_assertion(None, &create).is_err());
        assert!(
            validate_effect_assertion(
                Some(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1),
                &manifest("INSERT INTO items(id) VALUES (1);")
            )
            .is_err()
        );
        assert!(
            validate_effect_assertion(Some(EFFECT_ASSERTION_SCHEMA_CREATE_ONLY_V1), &create)
                .is_ok()
        );
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
        let query = build_fixed_query("d1_migrations", 1, &[], &[]);
        assert!(parse_complete_batch(&json!([]), &query.statements, &manifest).is_err());
        let table_query = build_fixed_query(
            "d1_migrations",
            1,
            &["items".to_string()],
            &["items".to_string()],
        );
        let mut result_sets = (0..table_query.statements.len())
            .map(|_| json!({"success": true, "results": []}))
            .collect::<Vec<_>>();
        result_sets[4] = json!({"success": true, "results": [{"table":"items","rowid":1,"parent":"parents","fkid":0}]});
        assert!(
            parse_complete_batch(&json!(result_sets), &table_query.statements, &manifest).is_err()
        );
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
        let validated = validate_expectations(1, vec![expected.clone()]).expect("expectations");
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
