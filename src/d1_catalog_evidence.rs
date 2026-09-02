//! Side-effect-free, exact D1 structured catalog projection evidence.
//!
//! This module owns one immutable catalog query/projection and verifies that two
//! adapter-issued frames claim distinct, primary-served, complete observations
//! whose canonical typed projections describe one stable snapshot for one
//! canonical D1 target. The fixed projection uses SQLite metadata for relation,
//! trigger-owner, and foreign-key facts. It retains table SQL bytes only as a
//! later AUTOINCREMENT token source and emits explicit conservative blockers
//! where structured metadata cannot prove later write semantics. It cannot
//! authenticate provider dispatch or response EOF; that custody belongs to the
//! internal provider adapter that constructs the frames. It deliberately does
//! not parse schema SQL, trigger bodies, or views and does not build or traverse
//! a write graph. It has no provider client, public tool route, or mutation
//! capability.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::d1_target::{D1TargetIdentity, normalize_d1_target};

pub(crate) const D1_CATALOG_EVIDENCE_OPERATION: &str = "d1_catalog_evidence";
pub(crate) const D1_CATALOG_MAX_ROWS: usize = 1_000;
pub(crate) const D1_CATALOG_PROVIDER_ROW_CAP: usize = D1_CATALOG_MAX_ROWS + 1;
pub(crate) const D1_CATALOG_PROVIDER_BYTE_CAP: usize = 4 * 1024 * 1024;

const D1_CATALOG_PROJECTION_VERSION: u8 = 2;
const D1_CATALOG_EVIDENCE_VERSION: u8 = 2;
const D1_CATALOG_QUERY: &str = "WITH \
relation_facts AS (SELECT 'relation' AS fact_kind, type AS relation_type, \
hex(CAST(name AS BLOB)) AS relation_name_hex, '' AS owner_name_hex, \
'' AS parent_name_hex, -1 AS foreign_key_id, -1 AS foreign_key_seq, \
'' AS on_update, '' AS on_delete, \
CASE WHEN type = 'view' THEN 'view_write_semantics_unproven' \
WHEN sql IS NULL THEN 'table_sql_token_source_unavailable' ELSE '' END AS conservative_blocker, \
CASE WHEN type = 'table' AND sql IS NOT NULL THEN 0 ELSE 1 END AS table_sql_token_source_is_null, \
CASE WHEN type = 'table' AND sql IS NOT NULL THEN hex(CAST(sql AS BLOB)) ELSE '' END AS table_sql_token_source_hex \
FROM sqlite_schema WHERE type IN ('table', 'view')), \
trigger_facts AS (SELECT 'trigger_owner' AS fact_kind, 'trigger' AS relation_type, \
hex(CAST(name AS BLOB)) AS relation_name_hex, \
CASE WHEN tbl_name IS NULL THEN '' ELSE hex(CAST(tbl_name AS BLOB)) END AS owner_name_hex, \
'' AS parent_name_hex, -1 AS foreign_key_id, -1 AS foreign_key_seq, \
'' AS on_update, '' AS on_delete, \
CASE WHEN EXISTS (SELECT 1 FROM sqlite_schema AS owner \
WHERE owner.type IN ('table', 'view') AND owner.name = trigger_row.tbl_name COLLATE NOCASE) \
THEN 'trigger_effects_unproven' ELSE 'trigger_owner_unresolved' END AS conservative_blocker, \
1 AS table_sql_token_source_is_null, '' AS table_sql_token_source_hex \
FROM sqlite_schema AS trigger_row WHERE type = 'trigger'), \
foreign_key_facts AS (SELECT 'foreign_key' AS fact_kind, 'table' AS relation_type, \
hex(CAST(child.name AS BLOB)) AS relation_name_hex, '' AS owner_name_hex, \
hex(CAST(fk.\"table\" AS BLOB)) AS parent_name_hex, \
fk.id AS foreign_key_id, fk.seq AS foreign_key_seq, \
fk.on_update AS on_update, fk.on_delete AS on_delete, \
CASE WHEN EXISTS (SELECT 1 FROM sqlite_schema AS parent \
WHERE parent.type = 'table' AND parent.name = fk.\"table\" COLLATE NOCASE) \
THEN '' ELSE 'foreign_key_parent_unresolved' END AS conservative_blocker, \
1 AS table_sql_token_source_is_null, '' AS table_sql_token_source_hex \
FROM sqlite_schema AS child JOIN pragma_foreign_key_list(child.name) AS fk \
WHERE child.type = 'table'), \
facts AS (SELECT * FROM relation_facts UNION ALL SELECT * FROM trigger_facts \
UNION ALL SELECT * FROM foreign_key_facts) \
SELECT fact_kind, relation_type, relation_name_hex, owner_name_hex, parent_name_hex, \
foreign_key_id, foreign_key_seq, on_update, on_delete, conservative_blocker, \
table_sql_token_source_is_null, table_sql_token_source_hex FROM facts \
ORDER BY fact_kind COLLATE BINARY, relation_type COLLATE BINARY, \
relation_name_hex COLLATE BINARY, owner_name_hex COLLATE BINARY, \
parent_name_hex COLLATE BINARY, foreign_key_id, foreign_key_seq, \
on_update COLLATE BINARY, on_delete COLLATE BINARY, conservative_blocker COLLATE BINARY, \
table_sql_token_source_is_null, table_sql_token_source_hex COLLATE BINARY LIMIT 1001";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1CatalogEvidencePlan {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) account_id: String,
    pub(crate) database_id: String,
    pub(crate) target_key_sha256: String,
    pub(crate) projection_version: u8,
    pub(crate) projection_fields: [&'static str; 12],
    pub(crate) query: &'static str,
    pub(crate) query_sha256: String,
    pub(crate) query_size_bytes: usize,
    pub(crate) max_catalog_rows: usize,
    pub(crate) provider_row_cap: usize,
    pub(crate) provider_byte_cap: usize,
}

/// Normalized evidence supplied only by the internal provider-custody adapter.
///
/// The adapter must allocate these identities before each physical request and
/// must set `body_complete` only after reading the complete bounded body. The
/// exact response body contains only the narrow projection payload below, not a
/// general Cloudflare envelope. This frame and its constructor do not
/// authenticate that dispatch or EOF; they preserve the adapter's claims for
/// deterministic verification.
pub(crate) struct D1CatalogObservationFrame<'a> {
    target: &'a D1TargetIdentity,
    query_plan_sha256: &'a str,
    dispatch_id: &'a str,
    read_id: &'a str,
    provider_row_cap: usize,
    provider_byte_cap: usize,
    body_complete: bool,
    body_size_bytes: usize,
    body: &'a [u8],
}

impl<'a> D1CatalogObservationFrame<'a> {
    /// Construct one normalized frame after the provider adapter has retained
    /// the corresponding provider-dispatch and complete-body evidence.
    ///
    /// Construction is intentionally crate-private and performs no provider or
    /// custody authentication. `prove_d1_catalog_evidence` validates every
    /// supplied field against the exact rederived plan.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_adapter_observation(
        target: &'a D1TargetIdentity,
        query_plan_sha256: &'a str,
        dispatch_id: &'a str,
        read_id: &'a str,
        provider_row_cap: usize,
        provider_byte_cap: usize,
        body_complete: bool,
        body_size_bytes: usize,
        body: &'a [u8],
    ) -> Self {
        Self {
            target,
            query_plan_sha256,
            dispatch_id,
            read_id,
            provider_row_cap,
            provider_byte_cap,
            body_complete,
            body_size_bytes,
            body,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1CatalogEvidenceReceipt {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) target_key_sha256: String,
    pub(crate) query_plan_sha256: String,
    pub(crate) query_sha256: String,
    pub(crate) projection_version: u8,
    pub(crate) catalog_snapshot_sha256: String,
    pub(crate) catalog_row_count: usize,
    pub(crate) relation_fact_count: usize,
    pub(crate) trigger_owner_fact_count: usize,
    pub(crate) foreign_key_fact_count: usize,
    pub(crate) conservative_blocker_count: usize,
    pub(crate) observation_pair_sha256: String,
    pub(crate) stable_primary_observations: u8,
    pub(crate) provider_row_cap: usize,
    pub(crate) provider_byte_cap: usize,
    pub(crate) response_body_sizes: [usize; 2],
}

/// Opaque verifier-issued structured projection for later pure consumers.
/// It cannot be created from caller JSON or a generic D1 response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1CatalogEvidenceProduct {
    receipt: D1CatalogEvidenceReceipt,
    rows: Vec<D1CatalogProjectionRow>,
}

impl D1CatalogEvidenceProduct {
    pub(crate) fn receipt(&self) -> &D1CatalogEvidenceReceipt {
        &self.receipt
    }

    pub(crate) fn rows(&self) -> &[D1CatalogProjectionRow] {
        &self.rows
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1CatalogEvidenceClassification {
    TargetIdentityInvalid,
    PlanDigestInvalid,
    PlanRederivationMismatch,
    ObservationTargetMismatch,
    ObservationPlanMismatch,
    ObservationIdentityInvalid,
    ObservationIdentityReused,
    ObservationCapMismatch,
    ObservationBodyIncomplete,
    ObservationBodySizeMismatch,
    ObservationBodyLimitExceeded,
    ObservationMalformed,
    ObservationTruncated,
    ObservationQueryFailed,
    ObservationNotPrimary,
    ObservationReportedMutation,
    CatalogRowLimitExceeded,
    CatalogRowMalformed,
    CatalogRowsNonCanonical,
    CatalogFactsContradictory,
    CatalogSnapshotsUnstable,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1CatalogEvidenceError {
    pub(crate) code: &'static str,
    pub(crate) classification: D1CatalogEvidenceClassification,
    pub(crate) message: &'static str,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct D1CatalogProjectionPayload {
    version: u8,
    results_truncated: bool,
    meta: D1CatalogReadMetadata,
    rows: Vec<D1CatalogProjectionRow>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct D1CatalogReadMetadata {
    query_succeeded: bool,
    served_by_primary: bool,
    changed_db: bool,
    changes: u64,
    rows_written: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct D1CatalogProjectionRow {
    pub(crate) fact_kind: String,
    pub(crate) relation_type: String,
    pub(crate) relation_name_hex: String,
    pub(crate) owner_name_hex: String,
    pub(crate) parent_name_hex: String,
    pub(crate) foreign_key_id: i64,
    pub(crate) foreign_key_seq: i64,
    pub(crate) on_update: String,
    pub(crate) on_delete: String,
    pub(crate) conservative_blocker: String,
    pub(crate) table_sql_token_source_is_null: u8,
    pub(crate) table_sql_token_source_hex: String,
}

pub(crate) fn derive_d1_catalog_evidence_plan(
    target: &D1TargetIdentity,
) -> Result<(D1CatalogEvidencePlan, String), D1CatalogEvidenceError> {
    if !canonical_target(target) {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::TargetIdentityInvalid,
            "catalog evidence did not receive one canonical D1 target",
        ));
    }

    let plan = D1CatalogEvidencePlan {
        version: D1_CATALOG_EVIDENCE_VERSION,
        operation: D1_CATALOG_EVIDENCE_OPERATION,
        account_id: target.account_id.clone(),
        database_id: target.database_id.clone(),
        target_key_sha256: target.target_key_sha256(),
        projection_version: D1_CATALOG_PROJECTION_VERSION,
        projection_fields: [
            "fact_kind",
            "relation_type",
            "relation_name_hex",
            "owner_name_hex",
            "parent_name_hex",
            "foreign_key_id",
            "foreign_key_seq",
            "on_update",
            "on_delete",
            "conservative_blocker",
            "table_sql_token_source_is_null",
            "table_sql_token_source_hex",
        ],
        query: D1_CATALOG_QUERY,
        query_sha256: sha256_hex(D1_CATALOG_QUERY.as_bytes()),
        query_size_bytes: D1_CATALOG_QUERY.len(),
        max_catalog_rows: D1_CATALOG_MAX_ROWS,
        provider_row_cap: D1_CATALOG_PROVIDER_ROW_CAP,
        provider_byte_cap: D1_CATALOG_PROVIDER_BYTE_CAP,
    };
    let plan_sha256 = hash_serialized(&plan);
    Ok((plan, plan_sha256))
}

pub(crate) fn prove_d1_catalog_evidence(
    target: &D1TargetIdentity,
    supplied_plan: &D1CatalogEvidencePlan,
    expected_plan_sha256: &str,
    first: &D1CatalogObservationFrame<'_>,
    second: &D1CatalogObservationFrame<'_>,
) -> Result<D1CatalogEvidenceReceipt, D1CatalogEvidenceError> {
    prove_d1_catalog_product(target, supplied_plan, expected_plan_sha256, first, second)
        .map(|product| product.receipt)
}

pub(crate) fn prove_d1_catalog_product(
    target: &D1TargetIdentity,
    supplied_plan: &D1CatalogEvidencePlan,
    expected_plan_sha256: &str,
    first: &D1CatalogObservationFrame<'_>,
    second: &D1CatalogObservationFrame<'_>,
) -> Result<D1CatalogEvidenceProduct, D1CatalogEvidenceError> {
    if !canonical_sha256(expected_plan_sha256) {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::PlanDigestInvalid,
            "catalog evidence expected-plan identity was not canonical SHA-256",
        ));
    }
    let (derived_plan, derived_plan_sha256) = derive_d1_catalog_evidence_plan(target)?;
    if supplied_plan != &derived_plan || expected_plan_sha256 != derived_plan_sha256 {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::PlanRederivationMismatch,
            "catalog evidence plan did not exactly rederive for the canonical target",
        ));
    }

    let first_payload = validate_observation(&derived_plan, &derived_plan_sha256, first)?;
    let second_payload = validate_observation(&derived_plan, &derived_plan_sha256, second)?;

    let identities = [
        first.dispatch_id,
        first.read_id,
        second.dispatch_id,
        second.read_id,
    ];
    if identities
        .iter()
        .any(|identity| !canonical_observation_identity(identity))
    {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationIdentityInvalid,
            "catalog observation identity was not canonical bounded ASCII",
        ));
    }
    if identities.iter().copied().collect::<BTreeSet<_>>().len() != identities.len() {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationIdentityReused,
            "catalog observations did not prove four distinct dispatch and read identities",
        ));
    }

    if first_payload.rows != second_payload.rows {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::CatalogSnapshotsUnstable,
            "two complete primary catalog observations did not contain one stable full snapshot",
        ));
    }

    let relation_fact_count = first_payload
        .rows
        .iter()
        .filter(|row| row.fact_kind == "relation")
        .count();
    let trigger_owner_fact_count = first_payload
        .rows
        .iter()
        .filter(|row| row.fact_kind == "trigger_owner")
        .count();
    let foreign_key_fact_count = first_payload
        .rows
        .iter()
        .filter(|row| row.fact_kind == "foreign_key")
        .count();
    let conservative_blocker_count = first_payload
        .rows
        .iter()
        .filter(|row| !row.conservative_blocker.is_empty())
        .count();
    let receipt = D1CatalogEvidenceReceipt {
        version: D1_CATALOG_EVIDENCE_VERSION,
        operation: D1_CATALOG_EVIDENCE_OPERATION,
        target_key_sha256: derived_plan.target_key_sha256,
        query_plan_sha256: derived_plan_sha256,
        query_sha256: derived_plan.query_sha256,
        projection_version: derived_plan.projection_version,
        catalog_snapshot_sha256: hash_serialized(&first_payload.rows),
        catalog_row_count: first_payload.rows.len(),
        relation_fact_count,
        trigger_owner_fact_count,
        foreign_key_fact_count,
        conservative_blocker_count,
        observation_pair_sha256: hash_serialized(&identities),
        stable_primary_observations: 2,
        provider_row_cap: derived_plan.provider_row_cap,
        provider_byte_cap: derived_plan.provider_byte_cap,
        response_body_sizes: [first.body_size_bytes, second.body_size_bytes],
    };
    Ok(D1CatalogEvidenceProduct {
        receipt,
        rows: first_payload.rows,
    })
}

fn validate_observation(
    plan: &D1CatalogEvidencePlan,
    plan_sha256: &str,
    frame: &D1CatalogObservationFrame<'_>,
) -> Result<D1CatalogProjectionPayload, D1CatalogEvidenceError> {
    if !canonical_target(frame.target)
        || frame.target.account_id != plan.account_id
        || frame.target.database_id != plan.database_id
        || frame.target.target_key_sha256() != plan.target_key_sha256
    {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationTargetMismatch,
            "catalog observation was not bound to the plan target",
        ));
    }
    if frame.query_plan_sha256 != plan_sha256 {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationPlanMismatch,
            "catalog observation was not bound to the exact rederived query plan",
        ));
    }
    if frame.provider_row_cap != plan.provider_row_cap
        || frame.provider_byte_cap != plan.provider_byte_cap
    {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationCapMismatch,
            "catalog observation did not use the exact plan-bound row and byte caps",
        ));
    }
    if !frame.body_complete {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationBodyIncomplete,
            "catalog observation did not prove a complete provider response body",
        ));
    }
    validate_body_size(
        frame.body_size_bytes,
        frame.body.len(),
        plan.provider_byte_cap,
    )?;

    let payload: D1CatalogProjectionPayload = serde_json::from_slice(frame.body).map_err(|_| {
        evidence_error(
            D1CatalogEvidenceClassification::ObservationMalformed,
            "catalog observation was not the exact narrow projection payload",
        )
    })?;
    if payload.version != plan.projection_version {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationMalformed,
            "catalog observation projection version was not exact",
        ));
    }
    if payload.results_truncated {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationTruncated,
            "catalog observation reported truncated results",
        ));
    }
    if !payload.meta.query_succeeded {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationQueryFailed,
            "catalog observation did not prove a successful query",
        ));
    }
    if !payload.meta.served_by_primary {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationNotPrimary,
            "catalog observation did not prove primary service",
        ));
    }
    if payload.meta.changed_db || payload.meta.changes != 0 || payload.meta.rows_written != 0 {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationReportedMutation,
            "catalog observation did not prove exact read-only metadata",
        ));
    }
    if payload.rows.len() > plan.max_catalog_rows {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::CatalogRowLimitExceeded,
            "catalog observation reached the plan sentinel or exceeded the row boundary",
        ));
    }
    validate_projection_rows(&payload.rows)?;
    Ok(payload)
}

fn validate_projection_rows(rows: &[D1CatalogProjectionRow]) -> Result<(), D1CatalogEvidenceError> {
    let mut previous: Option<&D1CatalogProjectionRow> = None;
    for row in rows {
        if !canonical_upper_hex(&row.relation_name_hex, true)
            || !canonical_upper_hex(&row.owner_name_hex, true)
            || !canonical_upper_hex(&row.parent_name_hex, true)
            || !matches!(row.table_sql_token_source_is_null, 0 | 1)
            || !canonical_upper_hex(&row.table_sql_token_source_hex, true)
            || !canonical_row_shape(row)
        {
            return Err(evidence_error(
                D1CatalogEvidenceClassification::CatalogRowMalformed,
                "catalog projection row was not canonical typed evidence",
            ));
        }
        if previous.is_some_and(|prior| prior >= row) {
            return Err(evidence_error(
                D1CatalogEvidenceClassification::CatalogRowsNonCanonical,
                "catalog projection rows were duplicate or outside exact query order",
            ));
        }
        previous = Some(row);
    }
    validate_structured_relationships(rows)
}

fn canonical_row_shape(row: &D1CatalogProjectionRow) -> bool {
    match (row.fact_kind.as_str(), row.relation_type.as_str()) {
        ("relation", "table") => {
            row.owner_name_hex.is_empty()
                && row.parent_name_hex.is_empty()
                && row.foreign_key_id == -1
                && row.foreign_key_seq == -1
                && row.on_update.is_empty()
                && row.on_delete.is_empty()
                && ((row.table_sql_token_source_is_null == 0
                    && row.conservative_blocker.is_empty())
                    || (row.table_sql_token_source_is_null == 1
                        && row.table_sql_token_source_hex.is_empty()
                        && row.conservative_blocker == "table_sql_token_source_unavailable"))
        }
        ("relation", "view") => {
            row.owner_name_hex.is_empty()
                && row.parent_name_hex.is_empty()
                && row.foreign_key_id == -1
                && row.foreign_key_seq == -1
                && row.on_update.is_empty()
                && row.on_delete.is_empty()
                && row.conservative_blocker == "view_write_semantics_unproven"
                && row.table_sql_token_source_is_null == 1
                && row.table_sql_token_source_hex.is_empty()
        }
        ("trigger_owner", "trigger") => {
            row.parent_name_hex.is_empty()
                && row.foreign_key_id == -1
                && row.foreign_key_seq == -1
                && row.on_update.is_empty()
                && row.on_delete.is_empty()
                && matches!(
                    row.conservative_blocker.as_str(),
                    "trigger_effects_unproven" | "trigger_owner_unresolved"
                )
                && row.table_sql_token_source_is_null == 1
                && row.table_sql_token_source_hex.is_empty()
        }
        ("foreign_key", "table") => {
            row.owner_name_hex.is_empty()
                && row.foreign_key_id >= 0
                && row.foreign_key_seq >= 0
                && canonical_foreign_key_action(&row.on_update)
                && canonical_foreign_key_action(&row.on_delete)
                && matches!(
                    row.conservative_blocker.as_str(),
                    "" | "foreign_key_parent_unresolved"
                )
                && row.table_sql_token_source_is_null == 1
                && row.table_sql_token_source_hex.is_empty()
        }
        _ => false,
    }
}

fn canonical_foreign_key_action(value: &str) -> bool {
    matches!(
        value,
        "NO ACTION" | "RESTRICT" | "SET NULL" | "SET DEFAULT" | "CASCADE"
    )
}

fn validate_structured_relationships(
    rows: &[D1CatalogProjectionRow],
) -> Result<(), D1CatalogEvidenceError> {
    let mut relations = BTreeMap::new();
    let mut triggers = BTreeSet::new();
    for row in rows.iter().filter(|row| row.fact_kind == "relation") {
        let identity = sqlite_ascii_identity(&row.relation_name_hex)?;
        if relations
            .insert(identity, row.relation_type.as_str())
            .is_some()
        {
            return Err(contradictory_facts());
        }
    }
    for row in rows.iter().filter(|row| row.fact_kind == "trigger_owner") {
        let trigger = sqlite_ascii_identity(&row.relation_name_hex)?;
        if !triggers.insert(trigger) {
            return Err(contradictory_facts());
        }
        let owner = sqlite_ascii_identity(&row.owner_name_hex)?;
        let owner_present = relations.contains_key(&owner);
        if owner_present != (row.conservative_blocker == "trigger_effects_unproven") {
            return Err(contradictory_facts());
        }
    }

    let mut foreign_keys: BTreeMap<
        (Vec<u8>, i64),
        (Vec<u8>, String, String, String, BTreeSet<i64>),
    > = BTreeMap::new();
    for row in rows.iter().filter(|row| row.fact_kind == "foreign_key") {
        let child = sqlite_ascii_identity(&row.relation_name_hex)?;
        if relations.get(&child) != Some(&"table") {
            return Err(contradictory_facts());
        }
        let parent = sqlite_ascii_identity(&row.parent_name_hex)?;
        let parent_present = relations.get(&parent) == Some(&"table");
        if parent_present != row.conservative_blocker.is_empty() {
            return Err(contradictory_facts());
        }
        let entry = foreign_keys
            .entry((child, row.foreign_key_id))
            .or_insert_with(|| {
                (
                    parent.clone(),
                    row.on_update.clone(),
                    row.on_delete.clone(),
                    row.conservative_blocker.clone(),
                    BTreeSet::new(),
                )
            });
        if entry.0 != parent
            || entry.1 != row.on_update
            || entry.2 != row.on_delete
            || entry.3 != row.conservative_blocker
            || !entry.4.insert(row.foreign_key_seq)
        {
            return Err(contradictory_facts());
        }
    }
    for (_, _, _, _, sequences) in foreign_keys.values() {
        if sequences.iter().copied().ne(0..sequences.len() as i64) {
            return Err(contradictory_facts());
        }
    }
    Ok(())
}

fn sqlite_ascii_identity(value: &str) -> Result<Vec<u8>, D1CatalogEvidenceError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or_else(contradictory_facts)?;
        let low = hex_nibble(pair[1]).ok_or_else(contradictory_facts)?;
        let byte = (high << 4) | low;
        decoded.push(byte.to_ascii_lowercase());
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn contradictory_facts() -> D1CatalogEvidenceError {
    evidence_error(
        D1CatalogEvidenceClassification::CatalogFactsContradictory,
        "structured catalog facts contradicted their relation or constraint identities",
    )
}

fn validate_body_size(
    reported: usize,
    actual: usize,
    cap: usize,
) -> Result<(), D1CatalogEvidenceError> {
    if reported != actual {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationBodySizeMismatch,
            "catalog observation body size did not match the complete supplied bytes",
        ));
    }
    if actual > cap {
        return Err(evidence_error(
            D1CatalogEvidenceClassification::ObservationBodyLimitExceeded,
            "catalog observation body exceeded the exact plan-bound byte cap",
        ));
    }
    Ok(())
}

fn canonical_target(target: &D1TargetIdentity) -> bool {
    matches!(
        normalize_d1_target(&target.account_id, &target.database_id),
        Ok(canonical) if canonical == *target
    )
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn canonical_observation_identity(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn canonical_upper_hex(value: &str, empty_allowed: bool) -> bool {
    (empty_allowed || !value.is_empty())
        && value.len() % 2 == 0
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
}

fn hash_serialized<T: Serialize>(value: &T) -> String {
    sha256_hex(&serde_json::to_vec(value).expect("catalog evidence serialization is infallible"))
}

fn sha256_hex(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn evidence_error(
    classification: D1CatalogEvidenceClassification,
    message: &'static str,
) -> D1CatalogEvidenceError {
    D1CatalogEvidenceError {
        code: "d1.catalog_evidence_unproven",
        classification,
        message,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const DATABASE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn target() -> D1TargetIdentity {
        normalize_d1_target("acct-1", DATABASE_ID).expect("canonical target")
    }

    fn row(name: &str, definition: Option<&str>) -> Value {
        json!({
            "fact_kind": "relation",
            "relation_type": "table",
            "relation_name_hex": hex(name),
            "owner_name_hex": "",
            "parent_name_hex": "",
            "foreign_key_id": -1,
            "foreign_key_seq": -1,
            "on_update": "",
            "on_delete": "",
            "conservative_blocker": if definition.is_some() { "" } else { "table_sql_token_source_unavailable" },
            "table_sql_token_source_is_null": u8::from(definition.is_none()),
            "table_sql_token_source_hex": definition.map(hex).unwrap_or_default(),
        })
    }

    fn view(name: &str) -> Value {
        json!({
            "fact_kind": "relation",
            "relation_type": "view",
            "relation_name_hex": hex(name),
            "owner_name_hex": "",
            "parent_name_hex": "",
            "foreign_key_id": -1,
            "foreign_key_seq": -1,
            "on_update": "",
            "on_delete": "",
            "conservative_blocker": "view_write_semantics_unproven",
            "table_sql_token_source_is_null": 1,
            "table_sql_token_source_hex": "",
        })
    }

    fn trigger(name: &str, owner: &str, owner_resolved: bool) -> Value {
        json!({
            "fact_kind": "trigger_owner",
            "relation_type": "trigger",
            "relation_name_hex": hex(name),
            "owner_name_hex": hex(owner),
            "parent_name_hex": "",
            "foreign_key_id": -1,
            "foreign_key_seq": -1,
            "on_update": "",
            "on_delete": "",
            "conservative_blocker": if owner_resolved { "trigger_effects_unproven" } else { "trigger_owner_unresolved" },
            "table_sql_token_source_is_null": 1,
            "table_sql_token_source_hex": "",
        })
    }

    fn foreign_key(
        child: &str,
        parent: &str,
        id: i64,
        seq: i64,
        on_update: &str,
        on_delete: &str,
        parent_resolved: bool,
    ) -> Value {
        json!({
            "fact_kind": "foreign_key",
            "relation_type": "table",
            "relation_name_hex": hex(child),
            "owner_name_hex": "",
            "parent_name_hex": hex(parent),
            "foreign_key_id": id,
            "foreign_key_seq": seq,
            "on_update": on_update,
            "on_delete": on_delete,
            "conservative_blocker": if parent_resolved { "" } else { "foreign_key_parent_unresolved" },
            "table_sql_token_source_is_null": 1,
            "table_sql_token_source_hex": "",
        })
    }

    fn hex(value: &str) -> String {
        value
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect()
    }

    fn payload(rows: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": 2,
            "results_truncated": false,
            "meta": {
                "query_succeeded": true,
                "served_by_primary": true,
                "changed_db": false,
                "changes": 0,
                "rows_written": 0,
            },
            "rows": rows,
        }))
        .expect("fixture payload")
    }

    fn frame<'a>(
        target: &'a D1TargetIdentity,
        plan_sha256: &'a str,
        dispatch_id: &'a str,
        read_id: &'a str,
        body: &'a [u8],
    ) -> D1CatalogObservationFrame<'a> {
        D1CatalogObservationFrame::from_adapter_observation(
            target,
            plan_sha256,
            dispatch_id,
            read_id,
            D1_CATALOG_PROVIDER_ROW_CAP,
            D1_CATALOG_PROVIDER_BYTE_CAP,
            true,
            body.len(),
            body,
        )
    }

    fn prove(
        plan: &D1CatalogEvidencePlan,
        plan_sha256: &str,
        first: &D1CatalogObservationFrame<'_>,
        second: &D1CatalogObservationFrame<'_>,
    ) -> Result<D1CatalogEvidenceReceipt, D1CatalogEvidenceError> {
        prove_d1_catalog_evidence(&target(), plan, plan_sha256, first, second)
    }

    fn classification(
        plan: &D1CatalogEvidencePlan,
        plan_sha256: &str,
        first: &D1CatalogObservationFrame<'_>,
        second: &D1CatalogObservationFrame<'_>,
    ) -> D1CatalogEvidenceClassification {
        prove(plan, plan_sha256, first, second)
            .expect_err("fixture must fail closed")
            .classification
    }

    #[test]
    fn plan_is_exact_fixed_projection_for_one_canonical_target() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        assert_eq!(plan.version, 2);
        assert_eq!(plan.projection_version, 2);
        assert_eq!(
            plan.projection_fields,
            [
                "fact_kind",
                "relation_type",
                "relation_name_hex",
                "owner_name_hex",
                "parent_name_hex",
                "foreign_key_id",
                "foreign_key_seq",
                "on_update",
                "on_delete",
                "conservative_blocker",
                "table_sql_token_source_is_null",
                "table_sql_token_source_hex",
            ]
        );
        assert_eq!(plan.target_key_sha256, target.target_key_sha256());
        assert_eq!(plan.query, D1_CATALOG_QUERY);
        assert_eq!(plan.query_sha256, sha256_hex(D1_CATALOG_QUERY.as_bytes()));
        assert_eq!(plan.provider_row_cap, 1_001);
        assert_eq!(plan.provider_byte_cap, 4 * 1024 * 1024);
        assert!(canonical_sha256(&plan_sha256));

        let mut weaker = plan.clone();
        weaker.query = "SELECT type, name FROM sqlite_schema LIMIT 1001";
        let body = payload(vec![]);
        let first = frame(
            &target,
            &plan_sha256,
            "dispatch-first-0001",
            "read-first-00000001",
            &body,
        );
        let second = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &body,
        );
        assert_eq!(
            classification(&weaker, &plan_sha256, &first, &second),
            D1CatalogEvidenceClassification::PlanRederivationMismatch
        );

        assert_eq!(
            prove(&plan, "A", &first, &second)
                .expect_err("noncanonical plan digest")
                .classification,
            D1CatalogEvidenceClassification::PlanDigestInvalid
        );

        let malformed_target = D1TargetIdentity {
            account_id: " acct-1".to_string(),
            database_id: DATABASE_ID.to_string(),
        };
        assert_eq!(
            derive_d1_catalog_evidence_plan(&malformed_target)
                .expect_err("target alias")
                .classification,
            D1CatalogEvidenceClassification::TargetIdentityInvalid
        );
    }

    #[test]
    fn stable_independent_primary_complete_observations_produce_aggregate_receipt() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let body = payload(vec![row("alpha", Some("CREATE TABLE alpha (id INTEGER)"))]);
        let first = frame(
            &target,
            &plan_sha256,
            "dispatch-first-0001",
            "read-first-00000001",
            &body,
        );
        let second = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &body,
        );
        let receipt = prove(&plan, &plan_sha256, &first, &second).expect("stable evidence");
        assert_eq!(receipt.catalog_row_count, 1);
        assert_eq!(receipt.relation_fact_count, 1);
        assert_eq!(receipt.trigger_owner_fact_count, 0);
        assert_eq!(receipt.foreign_key_fact_count, 0);
        assert_eq!(receipt.conservative_blocker_count, 0);
        assert_eq!(receipt.stable_primary_observations, 2);
        assert_eq!(receipt.response_body_sizes, [body.len(), body.len()]);
        let encoded = serde_json::to_string(&receipt).expect("receipt");
        assert!(!encoded.contains("alpha"));
        assert!(!encoded.contains("dispatch-first"));
        assert!(!encoded.contains(DATABASE_ID));
    }

    #[test]
    fn another_target_plan_or_reused_identity_fails_closed() {
        let target = target();
        let other = normalize_d1_target("acct-1", "223e4567-e89b-42d3-a456-426614174000")
            .expect("other target");
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let body = payload(vec![]);
        let good = frame(
            &target,
            &plan_sha256,
            "dispatch-first-0001",
            "read-first-00000001",
            &body,
        );
        let wrong_target = frame(
            &other,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &body,
        );
        assert_eq!(
            classification(&plan, &plan_sha256, &good, &wrong_target),
            D1CatalogEvidenceClassification::ObservationTargetMismatch
        );

        let wrong_plan_sha = "a".repeat(64);
        let wrong_plan = frame(
            &target,
            &wrong_plan_sha,
            "dispatch-second-001",
            "read-second-0000001",
            &body,
        );
        assert_eq!(
            classification(&plan, &plan_sha256, &good, &wrong_plan),
            D1CatalogEvidenceClassification::ObservationPlanMismatch
        );

        let reused = frame(
            &target,
            &plan_sha256,
            "dispatch-first-0001",
            "read-second-0000001",
            &body,
        );
        assert_eq!(
            classification(&plan, &plan_sha256, &good, &reused),
            D1CatalogEvidenceClassification::ObservationIdentityReused
        );
    }

    #[test]
    fn completeness_caps_and_body_size_are_exact() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let body = payload(vec![]);
        let first = frame(
            &target,
            &plan_sha256,
            "dispatch-first-0001",
            "read-first-00000001",
            &body,
        );
        let mut second = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &body,
        );

        second.body_complete = false;
        assert_eq!(
            classification(&plan, &plan_sha256, &first, &second),
            D1CatalogEvidenceClassification::ObservationBodyIncomplete
        );
        second.body_complete = true;
        second.provider_row_cap = 1_000;
        assert_eq!(
            classification(&plan, &plan_sha256, &first, &second),
            D1CatalogEvidenceClassification::ObservationCapMismatch
        );
        second.provider_row_cap = D1_CATALOG_PROVIDER_ROW_CAP;
        second.provider_byte_cap -= 1;
        assert_eq!(
            classification(&plan, &plan_sha256, &first, &second),
            D1CatalogEvidenceClassification::ObservationCapMismatch
        );
        second.provider_byte_cap = D1_CATALOG_PROVIDER_BYTE_CAP;
        second.body_size_bytes += 1;
        assert_eq!(
            classification(&plan, &plan_sha256, &first, &second),
            D1CatalogEvidenceClassification::ObservationBodySizeMismatch
        );
        assert_eq!(
            validate_body_size(
                D1_CATALOG_PROVIDER_BYTE_CAP + 1,
                D1_CATALOG_PROVIDER_BYTE_CAP + 1,
                D1_CATALOG_PROVIDER_BYTE_CAP,
            )
            .expect_err("byte overflow")
            .classification,
            D1CatalogEvidenceClassification::ObservationBodyLimitExceeded
        );
    }

    #[test]
    fn arbitrary_missing_nonboolean_and_truncated_json_fail_closed() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let valid_body = payload(vec![]);
        let first = frame(
            &target,
            &plan_sha256,
            "dispatch-first-0001",
            "read-first-00000001",
            &valid_body,
        );

        for body in [
            br#"{}"#.to_vec(),
            br#"[]"#.to_vec(),
            br#"{"version":2,"meta":{"query_succeeded":true,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0},"rows":[]}"#.to_vec(),
            br#"{"version":2,"results_truncated":"false","meta":{"query_succeeded":true,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0},"rows":[]}"#.to_vec(),
            br#"{"version":2,"results_truncated":false,"results_truncated":false,"meta":{"query_succeeded":true,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0},"rows":[]}"#.to_vec(),
            br#"{"version":2,"results_truncated":false,"meta":{"query_succeeded":true,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0},"rows":[],"arbitrary":true}"#.to_vec(),
        ] {
            let second = frame(
                &target,
                &plan_sha256,
                "dispatch-second-001",
                "read-second-0000001",
                &body,
            );
            assert_eq!(
                classification(&plan, &plan_sha256, &first, &second),
                D1CatalogEvidenceClassification::ObservationMalformed
            );
        }

        let mut truncated: Value = serde_json::from_slice(&valid_body).expect("payload");
        truncated["results_truncated"] = json!(true);
        let truncated = serde_json::to_vec(&truncated).expect("truncated payload");
        let second = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &truncated,
        );
        assert_eq!(
            classification(&plan, &plan_sha256, &first, &second),
            D1CatalogEvidenceClassification::ObservationTruncated
        );
    }

    #[test]
    fn typed_primary_read_only_metadata_is_mandatory() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let valid_body = payload(vec![]);
        let first = frame(
            &target,
            &plan_sha256,
            "dispatch-first-0001",
            "read-first-00000001",
            &valid_body,
        );

        let cases = [
            (
                "query_succeeded",
                json!(false),
                D1CatalogEvidenceClassification::ObservationQueryFailed,
            ),
            (
                "served_by_primary",
                json!(false),
                D1CatalogEvidenceClassification::ObservationNotPrimary,
            ),
            (
                "changed_db",
                json!(true),
                D1CatalogEvidenceClassification::ObservationReportedMutation,
            ),
            (
                "changes",
                json!(1),
                D1CatalogEvidenceClassification::ObservationReportedMutation,
            ),
            (
                "rows_written",
                json!(1),
                D1CatalogEvidenceClassification::ObservationReportedMutation,
            ),
        ];
        for (field, value, expected) in cases {
            let mut changed: Value = serde_json::from_slice(&valid_body).expect("payload");
            changed["meta"][field] = value;
            let changed = serde_json::to_vec(&changed).expect("changed payload");
            let second = frame(
                &target,
                &plan_sha256,
                "dispatch-second-001",
                "read-second-0000001",
                &changed,
            );
            assert_eq!(
                classification(&plan, &plan_sha256, &first, &second),
                expected
            );
        }

        let mut nonboolean: Value = serde_json::from_slice(&valid_body).expect("payload");
        nonboolean["meta"]["served_by_primary"] = json!("true");
        let nonboolean = serde_json::to_vec(&nonboolean).expect("nonboolean payload");
        let second = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &nonboolean,
        );
        assert_eq!(
            classification(&plan, &plan_sha256, &first, &second),
            D1CatalogEvidenceClassification::ObservationMalformed
        );
    }

    #[test]
    fn structured_relation_trigger_and_foreign_key_facts_are_exact_and_aggregate_safe() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let body = payload(vec![
            foreign_key("child", "parent", 0, 0, "SET NULL", "CASCADE", true),
            row(
                "child",
                Some("CREATE TABLE child(parent_id REFERENCES parent(id))"),
            ),
            row(
                "parent",
                Some("CREATE TABLE parent(id INTEGER PRIMARY KEY)"),
            ),
            view("parent_view"),
            trigger("child_after_insert", "child", true),
        ]);
        let first = frame(
            &target,
            &plan_sha256,
            "dispatch-first-0001",
            "read-first-00000001",
            &body,
        );
        let second = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &body,
        );
        let product = prove_d1_catalog_product(&target, &plan, &plan_sha256, &first, &second)
            .expect("structured product");
        assert_eq!(product.rows().len(), 5);
        assert_eq!(product.receipt().relation_fact_count, 3);
        assert_eq!(product.receipt().trigger_owner_fact_count, 1);
        assert_eq!(product.receipt().foreign_key_fact_count, 1);
        assert_eq!(product.receipt().conservative_blocker_count, 2);
        let encoded = serde_json::to_string(product.receipt()).expect("receipt");
        for private_value in ["child", "parent", "CASCADE", "CREATE TABLE"] {
            assert!(!encoded.contains(private_value));
        }
    }

    #[test]
    fn empty_sqlite_identifiers_remain_exact_structured_facts() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let body = payload(vec![
            row("", Some("CREATE TABLE \"\"(id INTEGER)")),
            trigger("", "", true),
        ]);
        let first = frame(
            &target,
            &plan_sha256,
            "dispatch-first-0001",
            "read-first-00000001",
            &body,
        );
        let second = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &body,
        );
        let product = prove_d1_catalog_product(&target, &plan, &plan_sha256, &first, &second)
            .expect("empty identifiers remain exact");
        assert_eq!(product.rows().len(), 2);
        assert_eq!(product.rows()[0].relation_name_hex, "");
        assert_eq!(product.rows()[1].owner_name_hex, "");
        assert_eq!(product.receipt().conservative_blocker_count, 1);
    }

    #[test]
    fn unresolved_structured_facts_require_exact_conservative_blockers() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let unresolved = payload(vec![
            foreign_key("child", "missing", 0, 0, "NO ACTION", "CASCADE", false),
            row(
                "child",
                Some("CREATE TABLE child(parent_id REFERENCES missing(id))"),
            ),
            row("opaque", None),
            trigger("orphaned", "missing", false),
        ]);
        let first = frame(
            &target,
            &plan_sha256,
            "dispatch-first-0001",
            "read-first-00000001",
            &unresolved,
        );
        let second = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &unresolved,
        );
        let receipt = prove(&plan, &plan_sha256, &first, &second).expect("blocked facts");
        assert_eq!(receipt.conservative_blocker_count, 3);

        let contradictory = payload(vec![
            foreign_key("child", "missing", 0, 0, "NO ACTION", "CASCADE", true),
            row(
                "child",
                Some("CREATE TABLE child(parent_id REFERENCES missing(id))"),
            ),
        ]);
        let contradictory_frame = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &contradictory,
        );
        assert_eq!(
            classification(
                &plan,
                &plan_sha256,
                &contradictory_frame,
                &contradictory_frame
            ),
            D1CatalogEvidenceClassification::CatalogFactsContradictory
        );

        let sequence_gap = payload(vec![
            foreign_key("child", "parent", 0, 1, "NO ACTION", "CASCADE", true),
            row(
                "child",
                Some("CREATE TABLE child(parent_id REFERENCES parent(id))"),
            ),
            row(
                "parent",
                Some("CREATE TABLE parent(id INTEGER PRIMARY KEY)"),
            ),
        ]);
        let sequence_gap_frame = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &sequence_gap,
        );
        assert_eq!(
            classification(
                &plan,
                &plan_sha256,
                &sequence_gap_frame,
                &sequence_gap_frame
            ),
            D1CatalogEvidenceClassification::CatalogFactsContradictory
        );
    }

    #[test]
    fn row_sentinel_projection_shape_order_and_stability_fail_closed() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let one_thousand = (0..1_000)
            .map(|index| {
                row(
                    &format!("table_{index:04}"),
                    Some("CREATE TABLE x (id INTEGER)"),
                )
            })
            .collect::<Vec<_>>();
        let complete = payload(one_thousand.clone());
        let first = frame(
            &target,
            &plan_sha256,
            "dispatch-first-0001",
            "read-first-00000001",
            &complete,
        );
        let second = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &complete,
        );
        assert!(prove(&plan, &plan_sha256, &first, &second).is_ok());

        let mut sentinel_rows = one_thousand;
        sentinel_rows.push(row("table_1000", Some("CREATE TABLE x (id INTEGER)")));
        let sentinel = payload(sentinel_rows);
        let second = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &sentinel,
        );
        assert_eq!(
            classification(&plan, &plan_sha256, &first, &second),
            D1CatalogEvidenceClassification::CatalogRowLimitExceeded
        );

        let malformed = payload(vec![json!({
            "fact_kind": "relation",
            "relation_type": "table",
            "relation_name_hex": "lowercase",
            "owner_name_hex": "",
            "parent_name_hex": "",
            "foreign_key_id": -1,
            "foreign_key_seq": -1,
            "on_update": "",
            "on_delete": "",
            "conservative_blocker": "",
            "table_sql_token_source_is_null": 1,
            "table_sql_token_source_hex": "AA",
        })]);
        let malformed_frame = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &malformed,
        );
        assert_eq!(
            classification(&plan, &plan_sha256, &first, &malformed_frame),
            D1CatalogEvidenceClassification::CatalogRowMalformed
        );

        let out_of_order = payload(vec![
            row("zeta", Some("CREATE TABLE zeta (id INTEGER)")),
            row("alpha", Some("CREATE TABLE alpha (id INTEGER)")),
        ]);
        let out_of_order_frame = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &out_of_order,
        );
        assert_eq!(
            classification(&plan, &plan_sha256, &first, &out_of_order_frame),
            D1CatalogEvidenceClassification::CatalogRowsNonCanonical
        );

        let changed = payload(vec![row(
            "different",
            Some("CREATE TABLE different (id INTEGER)"),
        )]);
        let first_changed = frame(
            &target,
            &plan_sha256,
            "dispatch-first-0001",
            "read-first-00000001",
            &changed,
        );
        let second_empty_body = payload(vec![]);
        let second_empty = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &second_empty_body,
        );
        assert_eq!(
            classification(&plan, &plan_sha256, &first_changed, &second_empty),
            D1CatalogEvidenceClassification::CatalogSnapshotsUnstable
        );
    }
}
