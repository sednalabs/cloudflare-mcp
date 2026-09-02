//! Side-effect-free, exact D1 structured catalog projection evidence.
//!
//! This module owns one immutable catalog query/projection and verifies that two
//! adapter-issued frames claim distinct, primary-served, complete observations
//! whose canonical typed projections describe one stable snapshot for one
//! canonical D1 target. The fixed projection enumerates every physical schema
//! row, preserves storage classes, and uses SQLite metadata for relation,
//! trigger-owner, and complete foreign-key facts including from/to/match. Only
//! structurally canonical TEXT child identities reach the foreign-key PRAGMA.
//! It retains table SQL bytes and permits only bounded later ASCII token
//! classification for AUTOINCREMENT and virtual-table evidence. It emits
//! explicit conservative blockers where structured metadata cannot prove later
//! write semantics. It cannot
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
pub(crate) const D1_CATALOG_TABLE_SQL_TOKEN_SOURCE_BYTE_CAP: usize = 64 * 1024;

const D1_CATALOG_PROJECTION_VERSION: u8 = 4;
const D1_CATALOG_EVIDENCE_VERSION: u8 = 4;
const D1_CATALOG_QUERY: &str = r#"WITH
schema_raw AS (
  SELECT rowid AS schema_rowid,
    type AS raw_type, typeof(type) AS type_storage_class, hex(type) AS type_value_hex,
    name AS raw_name, typeof(name) AS name_storage_class, hex(name) AS name_hex,
    tbl_name AS raw_owner, typeof(tbl_name) AS owner_storage_class, hex(tbl_name) AS owner_hex,
    sql AS raw_sql, typeof(sql) AS sql_storage_class
  FROM sqlite_schema
),
schema_enriched AS (
  SELECT candidate.*,
    (SELECT count(*) FROM schema_raw AS claimant
      WHERE claimant.name_hex = candidate.name_hex COLLATE BINARY
         OR (claimant.name_storage_class = 'text'
             AND candidate.name_storage_class = 'text'
             AND claimant.raw_name = candidate.raw_name COLLATE NOCASE)) AS name_claimant_count
  FROM schema_raw AS candidate
),
schema_classified AS (
  SELECT candidate.*,
    CASE
      WHEN type_storage_class != 'text' THEN 'schema_type_storage_class_invalid'
      WHEN raw_type NOT IN ('table', 'view', 'trigger', 'index') THEN 'schema_type_value_invalid'
      WHEN name_storage_class != 'text' THEN 'schema_name_storage_class_invalid'
      WHEN instr(CAST(raw_name AS BLOB), X'00') != 0 THEN 'schema_name_contains_nul'
      WHEN raw_name GLOB '*[^ -~]*' THEN 'schema_name_noncanonical_text'
      WHEN owner_storage_class != 'text' THEN 'schema_owner_storage_class_invalid'
      WHEN instr(CAST(raw_owner AS BLOB), X'00') != 0 THEN 'schema_owner_contains_nul'
      WHEN raw_owner GLOB '*[^ -~]*' THEN 'schema_owner_noncanonical_text'
      WHEN sql_storage_class NOT IN ('null', 'text') THEN 'schema_sql_storage_class_invalid'
      WHEN name_claimant_count != 1 THEN 'schema_identity_ambiguous'
      WHEN raw_type IN ('table', 'view') AND raw_name != raw_owner COLLATE NOCASE
        THEN 'relation_owner_mismatch'
      WHEN raw_type IN ('trigger', 'index') AND NOT EXISTS (
        SELECT 1 FROM schema_enriched AS owner
        WHERE owner.type_storage_class = 'text'
          AND owner.raw_type IN ('table', 'view')
          AND owner.name_storage_class = 'text'
          AND instr(CAST(owner.raw_name AS BLOB), X'00') = 0
          AND owner.raw_name NOT GLOB '*[^ -~]*'
          AND owner.owner_storage_class = 'text'
          AND instr(CAST(owner.raw_owner AS BLOB), X'00') = 0
          AND owner.raw_owner NOT GLOB '*[^ -~]*'
          AND owner.sql_storage_class IN ('null', 'text')
          AND owner.name_claimant_count = 1
          AND owner.raw_name = owner.raw_owner COLLATE NOCASE
          AND owner.raw_name = candidate.raw_owner COLLATE NOCASE)
        THEN 'schema_owner_unresolved'
      ELSE ''
    END AS structural_blocker
  FROM schema_enriched AS candidate
),
schema_facts AS (
  SELECT schema_rowid, 0 AS fact_order,
    CASE
      WHEN structural_blocker != '' THEN 'schema_blocker'
      WHEN raw_type IN ('table', 'view') THEN 'relation'
      WHEN raw_type = 'trigger' THEN 'trigger_owner'
      ELSE 'schema_auxiliary'
    END AS fact_kind,
    type_storage_class AS relation_type_storage_class,
    type_value_hex AS relation_type_value_hex,
    CASE WHEN type_storage_class = 'text'
           AND raw_type IN ('table', 'view', 'trigger', 'index')
      THEN raw_type ELSE '' END AS relation_type,
    name_storage_class AS relation_name_storage_class,
    name_hex AS relation_name_hex,
    owner_storage_class AS owner_name_storage_class,
    owner_hex AS owner_name_hex,
    sql_storage_class AS schema_sql_storage_class,
    CASE WHEN structural_blocker = '' AND raw_type = 'table' AND sql_storage_class = 'text'
      THEN 0 ELSE 1 END AS table_sql_token_source_is_null,
    CASE WHEN structural_blocker = '' AND raw_type = 'table' AND sql_storage_class = 'text'
      THEN hex(raw_sql) ELSE '' END AS table_sql_token_source_hex,
    CASE WHEN structural_blocker = '' AND raw_type = 'table' AND sql_storage_class = 'text'
        AND length(CAST(raw_sql AS BLOB)) <= 65536
        AND instr(lower(raw_sql), 'virtual') != 0
      THEN 1 ELSE 0 END AS table_virtual_token_hit,
    'not_applicable' AS foreign_key_id_storage_class, '' AS foreign_key_id_value_hex,
    -1 AS foreign_key_id,
    'not_applicable' AS foreign_key_seq_storage_class, '' AS foreign_key_seq_value_hex,
    -1 AS foreign_key_seq,
    'not_applicable' AS parent_name_storage_class, '' AS parent_name_hex,
    'not_applicable' AS from_column_storage_class, '' AS from_column_hex,
    'not_applicable' AS to_column_storage_class, 1 AS to_column_is_null, '' AS to_column_hex,
    'not_applicable' AS on_update_storage_class, '' AS on_update_hex,
    'not_applicable' AS on_delete_storage_class, '' AS on_delete_hex,
    'not_applicable' AS match_storage_class, '' AS match_hex,
    CASE
      WHEN structural_blocker != '' THEN structural_blocker
      WHEN raw_type = 'view' THEN 'view_write_semantics_unproven'
      WHEN raw_type = 'trigger' THEN 'trigger_effects_unproven'
      WHEN raw_type = 'table' AND sql_storage_class = 'null'
        THEN 'table_sql_token_source_unavailable'
      WHEN raw_type = 'table' AND sql_storage_class = 'text'
          AND length(CAST(raw_sql AS BLOB)) > 65536
        THEN 'table_sql_token_source_oversized'
      WHEN raw_type = 'table' AND sql_storage_class = 'text'
          AND instr(lower(raw_sql), 'virtual') != 0
        THEN 'table_virtual_semantics_unproven'
      ELSE ''
    END AS conservative_blocker
  FROM schema_classified
),
eligible_children AS (
  SELECT * FROM schema_classified
  WHERE structural_blocker = '' AND raw_type = 'table'
),
foreign_key_raw AS (
  SELECT child.schema_rowid, child.name_hex AS child_name_hex,
    fk.id AS raw_id, typeof(fk.id) AS id_storage_class, hex(fk.id) AS id_value_hex,
    fk.seq AS raw_seq, typeof(fk.seq) AS seq_storage_class, hex(fk.seq) AS seq_value_hex,
    fk."table" AS raw_parent, typeof(fk."table") AS parent_storage_class,
      hex(fk."table") AS parent_hex,
    fk."from" AS raw_from, typeof(fk."from") AS from_storage_class,
      hex(fk."from") AS from_hex,
    fk."to" AS raw_to, typeof(fk."to") AS to_storage_class, hex(fk."to") AS to_hex,
    fk.on_update AS raw_on_update, typeof(fk.on_update) AS on_update_storage_class,
      hex(fk.on_update) AS on_update_hex,
    fk.on_delete AS raw_on_delete, typeof(fk.on_delete) AS on_delete_storage_class,
      hex(fk.on_delete) AS on_delete_hex,
    fk."match" AS raw_match, typeof(fk."match") AS match_storage_class,
      hex(fk."match") AS match_hex
  FROM eligible_children AS child
  JOIN pragma_foreign_key_list(child.raw_name) AS fk
),
foreign_key_classified AS (
  SELECT foreign_key.*,
    CASE
      WHEN id_storage_class != 'integer' THEN 'foreign_key_id_storage_class_invalid'
      WHEN raw_id < 0 THEN 'foreign_key_id_value_invalid'
      WHEN seq_storage_class != 'integer' THEN 'foreign_key_seq_storage_class_invalid'
      WHEN raw_seq < 0 THEN 'foreign_key_seq_value_invalid'
      WHEN parent_storage_class != 'text' THEN 'foreign_key_parent_storage_class_invalid'
      WHEN instr(CAST(raw_parent AS BLOB), X'00') != 0 THEN 'foreign_key_parent_contains_nul'
      WHEN raw_parent GLOB '*[^ -~]*' THEN 'foreign_key_parent_noncanonical_text'
      WHEN from_storage_class != 'text' THEN 'foreign_key_from_storage_class_invalid'
      WHEN instr(CAST(raw_from AS BLOB), X'00') != 0 THEN 'foreign_key_from_contains_nul'
      WHEN raw_from GLOB '*[^ -~]*' THEN 'foreign_key_from_noncanonical_text'
      WHEN to_storage_class NOT IN ('null', 'text') THEN 'foreign_key_to_storage_class_invalid'
      WHEN to_storage_class = 'text' AND instr(CAST(raw_to AS BLOB), X'00') != 0
        THEN 'foreign_key_to_contains_nul'
      WHEN to_storage_class = 'text' AND raw_to GLOB '*[^ -~]*'
        THEN 'foreign_key_to_noncanonical_text'
      WHEN on_update_storage_class != 'text' THEN 'foreign_key_on_update_storage_class_invalid'
      WHEN raw_on_update NOT IN ('NO ACTION', 'RESTRICT', 'SET NULL', 'SET DEFAULT', 'CASCADE')
        THEN 'foreign_key_on_update_value_invalid'
      WHEN on_delete_storage_class != 'text' THEN 'foreign_key_on_delete_storage_class_invalid'
      WHEN raw_on_delete NOT IN ('NO ACTION', 'RESTRICT', 'SET NULL', 'SET DEFAULT', 'CASCADE')
        THEN 'foreign_key_on_delete_value_invalid'
      WHEN match_storage_class != 'text' THEN 'foreign_key_match_storage_class_invalid'
      WHEN raw_match NOT IN ('NONE', 'SIMPLE', 'PARTIAL', 'FULL')
        THEN 'foreign_key_match_value_invalid'
      ELSE ''
    END AS structural_blocker
  FROM foreign_key_raw AS foreign_key
),
foreign_key_facts AS (
  SELECT foreign_key.schema_rowid, 1 AS fact_order,
    CASE WHEN structural_blocker = '' THEN 'foreign_key' ELSE 'foreign_key_blocker' END AS fact_kind,
    'text' AS relation_type_storage_class, '7461626C65' AS relation_type_value_hex,
    'table' AS relation_type,
    'text' AS relation_name_storage_class, child_name_hex AS relation_name_hex,
    'not_applicable' AS owner_name_storage_class, '' AS owner_name_hex,
    'not_applicable' AS schema_sql_storage_class,
    1 AS table_sql_token_source_is_null, '' AS table_sql_token_source_hex,
    0 AS table_virtual_token_hit,
    id_storage_class AS foreign_key_id_storage_class,
    id_value_hex AS foreign_key_id_value_hex,
    CASE WHEN id_storage_class = 'integer' THEN raw_id ELSE -1 END AS foreign_key_id,
    seq_storage_class AS foreign_key_seq_storage_class,
    seq_value_hex AS foreign_key_seq_value_hex,
    CASE WHEN seq_storage_class = 'integer' THEN raw_seq ELSE -1 END AS foreign_key_seq,
    parent_storage_class AS parent_name_storage_class, parent_hex AS parent_name_hex,
    from_storage_class AS from_column_storage_class, from_hex AS from_column_hex,
    to_storage_class AS to_column_storage_class,
    CASE WHEN to_storage_class = 'null' THEN 1 ELSE 0 END AS to_column_is_null,
    to_hex AS to_column_hex,
    on_update_storage_class, on_update_hex,
    on_delete_storage_class, on_delete_hex,
    match_storage_class, match_hex,
    CASE
      WHEN structural_blocker != '' THEN structural_blocker
      WHEN NOT EXISTS (
        SELECT 1 FROM schema_classified AS parent
        WHERE parent.structural_blocker = '' AND parent.raw_type = 'table'
          AND parent.raw_name = foreign_key.raw_parent COLLATE NOCASE)
        THEN 'foreign_key_parent_unresolved'
      ELSE ''
    END AS conservative_blocker
  FROM foreign_key_classified AS foreign_key
),
facts AS (
  SELECT * FROM schema_facts
  UNION ALL
  SELECT * FROM foreign_key_facts
)
SELECT * FROM facts
ORDER BY schema_rowid, fact_order, fact_kind COLLATE BINARY,
  relation_type_storage_class COLLATE BINARY, relation_type_value_hex COLLATE BINARY,
  relation_type COLLATE BINARY, relation_name_storage_class COLLATE BINARY,
  relation_name_hex COLLATE BINARY, owner_name_storage_class COLLATE BINARY,
  owner_name_hex COLLATE BINARY, schema_sql_storage_class COLLATE BINARY,
  table_sql_token_source_is_null, table_sql_token_source_hex COLLATE BINARY,
  table_virtual_token_hit,
  foreign_key_id_storage_class COLLATE BINARY, foreign_key_id_value_hex COLLATE BINARY,
  foreign_key_id, foreign_key_seq_storage_class COLLATE BINARY,
  foreign_key_seq_value_hex COLLATE BINARY, foreign_key_seq,
  parent_name_storage_class COLLATE BINARY, parent_name_hex COLLATE BINARY,
  from_column_storage_class COLLATE BINARY, from_column_hex COLLATE BINARY,
  to_column_storage_class COLLATE BINARY, to_column_is_null, to_column_hex COLLATE BINARY,
  on_update_storage_class COLLATE BINARY, on_update_hex COLLATE BINARY,
  on_delete_storage_class COLLATE BINARY, on_delete_hex COLLATE BINARY,
  match_storage_class COLLATE BINARY, match_hex COLLATE BINARY,
  conservative_blocker COLLATE BINARY
LIMIT 1001"#;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1CatalogEvidencePlan {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) account_id: String,
    pub(crate) database_id: String,
    pub(crate) target_key_sha256: String,
    pub(crate) projection_version: u8,
    pub(crate) projection_fields: &'static [&'static str],
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
    pub(crate) schema_physical_row_count: usize,
    pub(crate) relation_fact_count: usize,
    pub(crate) trigger_owner_fact_count: usize,
    pub(crate) schema_auxiliary_fact_count: usize,
    pub(crate) schema_blocker_fact_count: usize,
    pub(crate) foreign_key_fact_count: usize,
    pub(crate) foreign_key_blocker_fact_count: usize,
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
    pub(crate) schema_rowid: i64,
    pub(crate) fact_order: u8,
    pub(crate) fact_kind: String,
    pub(crate) relation_type_storage_class: String,
    pub(crate) relation_type_value_hex: String,
    pub(crate) relation_type: String,
    pub(crate) relation_name_storage_class: String,
    pub(crate) relation_name_hex: String,
    pub(crate) owner_name_storage_class: String,
    pub(crate) owner_name_hex: String,
    pub(crate) schema_sql_storage_class: String,
    pub(crate) table_sql_token_source_is_null: u8,
    pub(crate) table_sql_token_source_hex: String,
    pub(crate) table_virtual_token_hit: u8,
    pub(crate) foreign_key_id_storage_class: String,
    pub(crate) foreign_key_id_value_hex: String,
    pub(crate) foreign_key_id: i64,
    pub(crate) foreign_key_seq_storage_class: String,
    pub(crate) foreign_key_seq_value_hex: String,
    pub(crate) foreign_key_seq: i64,
    pub(crate) parent_name_storage_class: String,
    pub(crate) parent_name_hex: String,
    pub(crate) from_column_storage_class: String,
    pub(crate) from_column_hex: String,
    pub(crate) to_column_storage_class: String,
    pub(crate) to_column_is_null: u8,
    pub(crate) to_column_hex: String,
    pub(crate) on_update_storage_class: String,
    pub(crate) on_update_hex: String,
    pub(crate) on_delete_storage_class: String,
    pub(crate) on_delete_hex: String,
    pub(crate) match_storage_class: String,
    pub(crate) match_hex: String,
    pub(crate) conservative_blocker: String,
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
        projection_fields: &[
            "schema_rowid",
            "fact_order",
            "fact_kind",
            "relation_type_storage_class",
            "relation_type_value_hex",
            "relation_type",
            "relation_name_storage_class",
            "relation_name_hex",
            "owner_name_storage_class",
            "owner_name_hex",
            "schema_sql_storage_class",
            "table_sql_token_source_is_null",
            "table_sql_token_source_hex",
            "table_virtual_token_hit",
            "foreign_key_id_storage_class",
            "foreign_key_id_value_hex",
            "foreign_key_id",
            "foreign_key_seq_storage_class",
            "foreign_key_seq_value_hex",
            "foreign_key_seq",
            "parent_name_storage_class",
            "parent_name_hex",
            "from_column_storage_class",
            "from_column_hex",
            "to_column_storage_class",
            "to_column_is_null",
            "to_column_hex",
            "on_update_storage_class",
            "on_update_hex",
            "on_delete_storage_class",
            "on_delete_hex",
            "match_storage_class",
            "match_hex",
            "conservative_blocker",
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
    let schema_physical_row_count = first_payload
        .rows
        .iter()
        .filter(|row| row.fact_order == 0)
        .count();
    let schema_auxiliary_fact_count = first_payload
        .rows
        .iter()
        .filter(|row| row.fact_kind == "schema_auxiliary")
        .count();
    let schema_blocker_fact_count = first_payload
        .rows
        .iter()
        .filter(|row| row.fact_kind == "schema_blocker")
        .count();
    let foreign_key_fact_count = first_payload
        .rows
        .iter()
        .filter(|row| row.fact_kind == "foreign_key")
        .count();
    let foreign_key_blocker_fact_count = first_payload
        .rows
        .iter()
        .filter(|row| row.fact_kind == "foreign_key_blocker")
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
        schema_physical_row_count,
        relation_fact_count,
        trigger_owner_fact_count,
        schema_auxiliary_fact_count,
        schema_blocker_fact_count,
        foreign_key_fact_count,
        foreign_key_blocker_fact_count,
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
        if !matches!(row.fact_order, 0 | 1)
            || !storage_hex_pair(
                &row.relation_type_storage_class,
                &row.relation_type_value_hex,
                false,
            )
            || !storage_hex_pair(
                &row.relation_name_storage_class,
                &row.relation_name_hex,
                false,
            )
            || !storage_hex_pair(&row.owner_name_storage_class, &row.owner_name_hex, true)
            || !matches!(
                row.schema_sql_storage_class.as_str(),
                "null" | "integer" | "real" | "text" | "blob" | "not_applicable"
            )
            || !matches!(row.table_sql_token_source_is_null, 0 | 1)
            || !canonical_upper_hex(&row.table_sql_token_source_hex, true)
            || !matches!(row.table_virtual_token_hit, 0 | 1)
            || !storage_hex_pair(
                &row.foreign_key_id_storage_class,
                &row.foreign_key_id_value_hex,
                true,
            )
            || !storage_hex_pair(
                &row.foreign_key_seq_storage_class,
                &row.foreign_key_seq_value_hex,
                true,
            )
            || !storage_hex_pair(&row.parent_name_storage_class, &row.parent_name_hex, true)
            || !storage_hex_pair(&row.from_column_storage_class, &row.from_column_hex, true)
            || !storage_hex_pair(&row.to_column_storage_class, &row.to_column_hex, true)
            || !matches!(row.to_column_is_null, 0 | 1)
            || !storage_hex_pair(&row.on_update_storage_class, &row.on_update_hex, true)
            || !storage_hex_pair(&row.on_delete_storage_class, &row.on_delete_hex, true)
            || !storage_hex_pair(&row.match_storage_class, &row.match_hex, true)
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

fn storage_hex_pair(storage: &str, value_hex: &str, not_applicable_allowed: bool) -> bool {
    (matches!(storage, "null" | "integer" | "real" | "text" | "blob")
        && canonical_upper_hex(value_hex, true)
        && (storage != "null" || value_hex.is_empty())
        && (!matches!(storage, "integer" | "real") || !value_hex.is_empty()))
        || (not_applicable_allowed && storage == "not_applicable" && value_hex.is_empty())
}

fn schema_fact_sentinels(row: &D1CatalogProjectionRow) -> bool {
    row.fact_order == 0
        && row.foreign_key_id_storage_class == "not_applicable"
        && row.foreign_key_id_value_hex.is_empty()
        && row.foreign_key_id == -1
        && row.foreign_key_seq_storage_class == "not_applicable"
        && row.foreign_key_seq_value_hex.is_empty()
        && row.foreign_key_seq == -1
        && row.parent_name_storage_class == "not_applicable"
        && row.parent_name_hex.is_empty()
        && row.from_column_storage_class == "not_applicable"
        && row.from_column_hex.is_empty()
        && row.to_column_storage_class == "not_applicable"
        && row.to_column_is_null == 1
        && row.to_column_hex.is_empty()
        && row.on_update_storage_class == "not_applicable"
        && row.on_update_hex.is_empty()
        && row.on_delete_storage_class == "not_applicable"
        && row.on_delete_hex.is_empty()
        && row.match_storage_class == "not_applicable"
        && row.match_hex.is_empty()
}

fn validate_structured_relationships(
    rows: &[D1CatalogProjectionRow],
) -> Result<(), D1CatalogEvidenceError> {
    let schema_rows = rows
        .iter()
        .filter(|row| row.fact_order == 0)
        .collect::<Vec<_>>();
    let mut schema_rowids = BTreeSet::new();
    for row in &schema_rows {
        if !schema_rowids.insert(row.schema_rowid)
            || !schema_fact_sentinels(row)
            || !validate_schema_fact(row, &schema_rows)?
        {
            return Err(contradictory_facts());
        }
    }

    let relations = schema_rows
        .iter()
        .filter(|row| row.fact_kind == "relation")
        .map(|row| {
            Ok((
                sqlite_ascii_identity(&row.relation_name_hex)?,
                row.relation_type.as_str(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, D1CatalogEvidenceError>>()?;

    let mut foreign_keys: BTreeMap<
        (Vec<u8>, i64),
        (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, BTreeSet<i64>),
    > = BTreeMap::new();
    for row in rows.iter().filter(|row| row.fact_order == 1) {
        let Some(child_schema) = schema_rows
            .iter()
            .find(|candidate| candidate.schema_rowid == row.schema_rowid)
        else {
            return Err(contradictory_facts());
        };
        if child_schema.fact_kind != "relation"
            || child_schema.relation_type != "table"
            || row.relation_type_storage_class != "text"
            || row.relation_type_value_hex != hex_bytes(b"table")
            || row.relation_type != "table"
            || row.relation_name_storage_class != "text"
            || row.relation_name_hex != child_schema.relation_name_hex
            || row.owner_name_storage_class != "not_applicable"
            || !row.owner_name_hex.is_empty()
            || row.schema_sql_storage_class != "not_applicable"
            || row.table_sql_token_source_is_null != 1
            || !row.table_sql_token_source_hex.is_empty()
            || row.table_virtual_token_hit != 0
            || !foreign_key_storage_markers_applicable(row)
        {
            return Err(contradictory_facts());
        }
        let structural_blocker = expected_foreign_key_structural_blocker(row)?;
        let child = sqlite_ascii_identity(&row.relation_name_hex)?;
        let parent = sqlite_ascii_identity(&row.parent_name_hex)?;
        let parent_present = relations.get(&parent) == Some(&"table");
        let expected_blocker = if !structural_blocker.is_empty() {
            structural_blocker
        } else if !parent_present {
            "foreign_key_parent_unresolved"
        } else {
            ""
        };
        let expected_kind = if structural_blocker.is_empty() {
            "foreign_key"
        } else {
            "foreign_key_blocker"
        };
        if row.fact_kind != expected_kind || row.conservative_blocker != expected_blocker {
            return Err(contradictory_facts());
        }
        if !structural_blocker.is_empty() {
            continue;
        }
        let entry = foreign_keys
            .entry((child, row.foreign_key_id))
            .or_insert_with(|| {
                (
                    parent.clone(),
                    decode_upper_hex(&row.on_update_hex).expect("validated hex"),
                    decode_upper_hex(&row.on_delete_hex).expect("validated hex"),
                    decode_upper_hex(&row.match_hex).expect("validated hex"),
                    row.conservative_blocker.clone(),
                    BTreeSet::new(),
                )
            });
        if entry.0 != parent
            || entry.1 != decode_upper_hex(&row.on_update_hex)?
            || entry.2 != decode_upper_hex(&row.on_delete_hex)?
            || entry.3 != decode_upper_hex(&row.match_hex)?
            || entry.4 != row.conservative_blocker
            || !entry.5.insert(row.foreign_key_seq)
        {
            return Err(contradictory_facts());
        }
    }
    for (_, _, _, _, _, sequences) in foreign_keys.values() {
        if sequences.iter().copied().ne(0..sequences.len() as i64) {
            return Err(contradictory_facts());
        }
    }
    Ok(())
}

fn foreign_key_storage_markers_applicable(row: &D1CatalogProjectionRow) -> bool {
    [
        row.foreign_key_id_storage_class.as_str(),
        row.foreign_key_seq_storage_class.as_str(),
        row.parent_name_storage_class.as_str(),
        row.from_column_storage_class.as_str(),
        row.to_column_storage_class.as_str(),
        row.on_update_storage_class.as_str(),
        row.on_delete_storage_class.as_str(),
        row.match_storage_class.as_str(),
    ]
    .iter()
    .all(|storage| *storage != "not_applicable")
}

fn validate_schema_fact(
    row: &D1CatalogProjectionRow,
    schema_rows: &[&D1CatalogProjectionRow],
) -> Result<bool, D1CatalogEvidenceError> {
    if row.relation_type_storage_class == "not_applicable"
        || row.relation_name_storage_class == "not_applicable"
        || row.owner_name_storage_class == "not_applicable"
        || row.schema_sql_storage_class == "not_applicable"
    {
        return Ok(false);
    }
    let recognized_type = recognized_schema_type(row);
    let expected_relation_type = recognized_type.unwrap_or("");
    if row.relation_type != expected_relation_type {
        return Ok(false);
    }
    let structural_blocker = expected_schema_structural_blocker(row, schema_rows)?;
    let expected_kind = if !structural_blocker.is_empty() {
        "schema_blocker"
    } else {
        match recognized_type {
            Some("table" | "view") => "relation",
            Some("trigger") => "trigger_owner",
            Some("index") => "schema_auxiliary",
            _ => return Ok(false),
        }
    };
    let token_source = if structural_blocker.is_empty()
        && recognized_type == Some("table")
        && row.schema_sql_storage_class == "text"
    {
        Some(decode_upper_hex(&row.table_sql_token_source_hex)?)
    } else {
        None
    };
    let token_source_oversized = token_source
        .as_ref()
        .is_some_and(|source| source.len() > D1_CATALOG_TABLE_SQL_TOKEN_SOURCE_BYTE_CAP);
    let virtual_token_hit = token_source
        .as_ref()
        .is_some_and(|source| contains_ascii_token(source, b"VIRTUAL"));
    let expected_blocker = if !structural_blocker.is_empty() {
        structural_blocker
    } else {
        match recognized_type {
            Some("view") => "view_write_semantics_unproven",
            Some("trigger") => "trigger_effects_unproven",
            Some("table") if row.schema_sql_storage_class == "null" => {
                "table_sql_token_source_unavailable"
            }
            Some("table") if token_source_oversized => "table_sql_token_source_oversized",
            Some("table") if virtual_token_hit => "table_virtual_semantics_unproven",
            _ => "",
        }
    };
    let token_available = structural_blocker.is_empty()
        && recognized_type == Some("table")
        && row.schema_sql_storage_class == "text";
    Ok(row.fact_kind == expected_kind
        && row.conservative_blocker == expected_blocker
        && row.table_sql_token_source_is_null == u8::from(!token_available)
        && (token_available || row.table_sql_token_source_hex.is_empty())
        && row.table_virtual_token_hit == u8::from(virtual_token_hit && !token_source_oversized))
}

fn contains_ascii_token(source: &[u8], token: &[u8]) -> bool {
    source.windows(token.len()).any(|window| {
        window
            .iter()
            .zip(token)
            .all(|(actual, expected)| actual.to_ascii_uppercase() == *expected)
    })
}

fn expected_schema_structural_blocker(
    row: &D1CatalogProjectionRow,
    schema_rows: &[&D1CatalogProjectionRow],
) -> Result<&'static str, D1CatalogEvidenceError> {
    if row.relation_type_storage_class != "text" {
        return Ok("schema_type_storage_class_invalid");
    }
    let Some(schema_type) = recognized_schema_type(row) else {
        return Ok("schema_type_value_invalid");
    };
    if row.relation_name_storage_class != "text" {
        return Ok("schema_name_storage_class_invalid");
    }
    let name = decode_upper_hex(&row.relation_name_hex)?;
    if name.contains(&0) {
        return Ok("schema_name_contains_nul");
    }
    if !printable_ascii(&name) {
        return Ok("schema_name_noncanonical_text");
    }
    if row.owner_name_storage_class != "text" {
        return Ok("schema_owner_storage_class_invalid");
    }
    let owner = decode_upper_hex(&row.owner_name_hex)?;
    if owner.contains(&0) {
        return Ok("schema_owner_contains_nul");
    }
    if !printable_ascii(&owner) {
        return Ok("schema_owner_noncanonical_text");
    }
    if !matches!(row.schema_sql_storage_class.as_str(), "null" | "text") {
        return Ok("schema_sql_storage_class_invalid");
    }
    let claimants = schema_rows
        .iter()
        .filter(|candidate| {
            candidate.relation_name_hex == row.relation_name_hex
                || (candidate.relation_name_storage_class == "text"
                    && row.relation_name_storage_class == "text"
                    && sqlite_ascii_bytes(&candidate.relation_name_hex).ok()
                        == sqlite_ascii_bytes(&row.relation_name_hex).ok())
        })
        .count();
    if claimants != 1 {
        return Ok("schema_identity_ambiguous");
    }
    if matches!(schema_type, "table" | "view")
        && sqlite_ascii_lower(&name) != sqlite_ascii_lower(&owner)
    {
        return Ok("relation_owner_mismatch");
    }
    if matches!(schema_type, "trigger" | "index")
        && !schema_rows.iter().any(|candidate| {
            recognized_schema_type(candidate).is_some_and(|value| matches!(value, "table" | "view"))
                && base_canonical_relation(candidate, schema_rows)
                && sqlite_ascii_bytes(&candidate.relation_name_hex).ok()
                    == Some(sqlite_ascii_lower(&owner))
        })
    {
        return Ok("schema_owner_unresolved");
    }
    Ok("")
}

fn base_canonical_relation(
    row: &D1CatalogProjectionRow,
    schema_rows: &[&D1CatalogProjectionRow],
) -> bool {
    matches!(recognized_schema_type(row), Some("table" | "view"))
        && row.relation_name_storage_class == "text"
        && row.owner_name_storage_class == "text"
        && matches!(row.schema_sql_storage_class.as_str(), "null" | "text")
        && decode_upper_hex(&row.relation_name_hex)
            .ok()
            .is_some_and(|value| printable_ascii(&value))
        && decode_upper_hex(&row.owner_name_hex)
            .ok()
            .is_some_and(|value| printable_ascii(&value))
        && sqlite_ascii_bytes(&row.relation_name_hex).ok()
            == sqlite_ascii_bytes(&row.owner_name_hex).ok()
        && schema_rows
            .iter()
            .filter(|candidate| {
                candidate.relation_name_hex == row.relation_name_hex
                    || (candidate.relation_name_storage_class == "text"
                        && sqlite_ascii_bytes(&candidate.relation_name_hex).ok()
                            == sqlite_ascii_bytes(&row.relation_name_hex).ok())
            })
            .count()
            == 1
}

fn expected_foreign_key_structural_blocker(
    row: &D1CatalogProjectionRow,
) -> Result<&'static str, D1CatalogEvidenceError> {
    if row.foreign_key_id_storage_class != "integer" {
        if row.foreign_key_id != -1 {
            return Err(contradictory_facts());
        }
        return Ok("foreign_key_id_storage_class_invalid");
    }
    if row.foreign_key_id_value_hex != hex_bytes(row.foreign_key_id.to_string().as_bytes())
        || row.foreign_key_id < 0
    {
        return Ok("foreign_key_id_value_invalid");
    }
    if row.foreign_key_seq_storage_class != "integer" {
        if row.foreign_key_seq != -1 {
            return Err(contradictory_facts());
        }
        return Ok("foreign_key_seq_storage_class_invalid");
    }
    if row.foreign_key_seq_value_hex != hex_bytes(row.foreign_key_seq.to_string().as_bytes())
        || row.foreign_key_seq < 0
    {
        return Ok("foreign_key_seq_value_invalid");
    }
    for (storage, value, storage_blocker, nul_blocker, text_blocker) in [
        (
            row.parent_name_storage_class.as_str(),
            row.parent_name_hex.as_str(),
            "foreign_key_parent_storage_class_invalid",
            "foreign_key_parent_contains_nul",
            "foreign_key_parent_noncanonical_text",
        ),
        (
            row.from_column_storage_class.as_str(),
            row.from_column_hex.as_str(),
            "foreign_key_from_storage_class_invalid",
            "foreign_key_from_contains_nul",
            "foreign_key_from_noncanonical_text",
        ),
    ] {
        if storage != "text" {
            return Ok(storage_blocker);
        }
        let decoded = decode_upper_hex(value)?;
        if decoded.contains(&0) {
            return Ok(nul_blocker);
        }
        if !printable_ascii(&decoded) {
            return Ok(text_blocker);
        }
    }
    if !matches!(row.to_column_storage_class.as_str(), "null" | "text") {
        return Ok("foreign_key_to_storage_class_invalid");
    }
    if row.to_column_is_null != u8::from(row.to_column_storage_class == "null") {
        return Ok("foreign_key_to_storage_class_invalid");
    }
    if row.to_column_storage_class == "text" {
        let to = decode_upper_hex(&row.to_column_hex)?;
        if to.contains(&0) {
            return Ok("foreign_key_to_contains_nul");
        }
        if !printable_ascii(&to) {
            return Ok("foreign_key_to_noncanonical_text");
        }
    }
    for (storage, value, storage_blocker, value_blocker, allowed) in [
        (
            row.on_update_storage_class.as_str(),
            row.on_update_hex.as_str(),
            "foreign_key_on_update_storage_class_invalid",
            "foreign_key_on_update_value_invalid",
            &[
                "NO ACTION",
                "RESTRICT",
                "SET NULL",
                "SET DEFAULT",
                "CASCADE",
            ][..],
        ),
        (
            row.on_delete_storage_class.as_str(),
            row.on_delete_hex.as_str(),
            "foreign_key_on_delete_storage_class_invalid",
            "foreign_key_on_delete_value_invalid",
            &[
                "NO ACTION",
                "RESTRICT",
                "SET NULL",
                "SET DEFAULT",
                "CASCADE",
            ][..],
        ),
        (
            row.match_storage_class.as_str(),
            row.match_hex.as_str(),
            "foreign_key_match_storage_class_invalid",
            "foreign_key_match_value_invalid",
            &["NONE", "SIMPLE", "PARTIAL", "FULL"][..],
        ),
    ] {
        if storage != "text" {
            return Ok(storage_blocker);
        }
        let decoded = decode_upper_hex(value)?;
        if !allowed.iter().any(|allowed| decoded == allowed.as_bytes()) {
            return Ok(value_blocker);
        }
    }
    Ok("")
}

fn recognized_schema_type(row: &D1CatalogProjectionRow) -> Option<&str> {
    if row.relation_type_storage_class != "text" {
        return None;
    }
    match decode_upper_hex(&row.relation_type_value_hex)
        .ok()?
        .as_slice()
    {
        b"table" => Some("table"),
        b"view" => Some("view"),
        b"trigger" => Some("trigger"),
        b"index" => Some("index"),
        _ => None,
    }
}

fn printable_ascii(value: &[u8]) -> bool {
    value.iter().all(|byte| matches!(*byte, b' '..=b'~'))
}

fn sqlite_ascii_lower(value: &[u8]) -> Vec<u8> {
    value.iter().map(u8::to_ascii_lowercase).collect()
}

fn sqlite_ascii_bytes(value: &str) -> Result<Vec<u8>, D1CatalogEvidenceError> {
    decode_upper_hex(value).map(|value| sqlite_ascii_lower(&value))
}

fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn decode_upper_hex(value: &str) -> Result<Vec<u8>, D1CatalogEvidenceError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or_else(contradictory_facts)?;
        let low = hex_nibble(pair[1]).ok_or_else(contradictory_facts)?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn sqlite_ascii_identity(value: &str) -> Result<Vec<u8>, D1CatalogEvidenceError> {
    sqlite_ascii_bytes(value)
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
    use std::io::Write;
    use std::process::{Command, Stdio};

    use serde_json::{Value, json};

    use super::*;

    const DATABASE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn target() -> D1TargetIdentity {
        normalize_d1_target("acct-1", DATABASE_ID).expect("canonical target")
    }

    fn schema_sentinels() -> Value {
        json!({
            "foreign_key_id_storage_class": "not_applicable",
            "foreign_key_id_value_hex": "",
            "foreign_key_id": -1,
            "foreign_key_seq_storage_class": "not_applicable",
            "foreign_key_seq_value_hex": "",
            "foreign_key_seq": -1,
            "parent_name_storage_class": "not_applicable",
            "parent_name_hex": "",
            "from_column_storage_class": "not_applicable",
            "from_column_hex": "",
            "to_column_storage_class": "not_applicable",
            "to_column_is_null": 1,
            "to_column_hex": "",
            "on_update_storage_class": "not_applicable",
            "on_update_hex": "",
            "on_delete_storage_class": "not_applicable",
            "on_delete_hex": "",
            "match_storage_class": "not_applicable",
            "match_hex": "",
        })
    }

    fn row(schema_rowid: i64, name: &str, definition: Option<&str>) -> Value {
        let oversized = definition
            .is_some_and(|source| source.len() > D1_CATALOG_TABLE_SQL_TOKEN_SOURCE_BYTE_CAP);
        let virtual_token_hit =
            definition.is_some_and(|source| contains_ascii_token(source.as_bytes(), b"VIRTUAL"));
        let blocker = if definition.is_none() {
            "table_sql_token_source_unavailable"
        } else if oversized {
            "table_sql_token_source_oversized"
        } else if virtual_token_hit {
            "table_virtual_semantics_unproven"
        } else {
            ""
        };
        let mut value = json!({
            "schema_rowid": schema_rowid,
            "fact_order": 0,
            "fact_kind": "relation",
            "relation_type_storage_class": "text",
            "relation_type_value_hex": hex("table"),
            "relation_type": "table",
            "relation_name_storage_class": "text",
            "relation_name_hex": hex(name),
            "owner_name_storage_class": "text",
            "owner_name_hex": hex(name),
            "schema_sql_storage_class": if definition.is_some() { "text" } else { "null" },
            "table_sql_token_source_is_null": u8::from(definition.is_none()),
            "table_sql_token_source_hex": definition.map(hex).unwrap_or_default(),
            "table_virtual_token_hit": u8::from(virtual_token_hit && !oversized),
            "conservative_blocker": blocker,
        });
        value
            .as_object_mut()
            .expect("schema row")
            .extend(schema_sentinels().as_object().expect("sentinels").clone());
        value
    }

    fn view(schema_rowid: i64, name: &str) -> Value {
        let mut value = json!({
            "schema_rowid": schema_rowid,
            "fact_order": 0,
            "fact_kind": "relation",
            "relation_type_storage_class": "text",
            "relation_type_value_hex": hex("view"),
            "relation_type": "view",
            "relation_name_storage_class": "text",
            "relation_name_hex": hex(name),
            "owner_name_storage_class": "text",
            "owner_name_hex": hex(name),
            "schema_sql_storage_class": "text",
            "table_sql_token_source_is_null": 1,
            "table_sql_token_source_hex": "",
            "table_virtual_token_hit": 0,
            "conservative_blocker": "view_write_semantics_unproven",
        });
        value
            .as_object_mut()
            .expect("view row")
            .extend(schema_sentinels().as_object().expect("sentinels").clone());
        value
    }

    fn trigger(schema_rowid: i64, name: &str, owner: &str, owner_resolved: bool) -> Value {
        let mut value = json!({
            "schema_rowid": schema_rowid,
            "fact_order": 0,
            "fact_kind": if owner_resolved { "trigger_owner" } else { "schema_blocker" },
            "relation_type_storage_class": "text",
            "relation_type_value_hex": hex("trigger"),
            "relation_type": "trigger",
            "relation_name_storage_class": "text",
            "relation_name_hex": hex(name),
            "owner_name_storage_class": "text",
            "owner_name_hex": hex(owner),
            "schema_sql_storage_class": "text",
            "table_sql_token_source_is_null": 1,
            "table_sql_token_source_hex": "",
            "table_virtual_token_hit": 0,
            "conservative_blocker": if owner_resolved { "trigger_effects_unproven" } else { "schema_owner_unresolved" },
        });
        value
            .as_object_mut()
            .expect("trigger row")
            .extend(schema_sentinels().as_object().expect("sentinels").clone());
        value
    }

    fn foreign_key(
        schema_rowid: i64,
        child: &str,
        parent: &str,
        id: i64,
        seq: i64,
        from_column: &str,
        to_column: Option<&str>,
        on_update: &str,
        on_delete: &str,
        match_mode: &str,
        parent_resolved: bool,
    ) -> Value {
        json!({
            "schema_rowid": schema_rowid,
            "fact_order": 1,
            "fact_kind": "foreign_key",
            "relation_type_storage_class": "text",
            "relation_type_value_hex": hex("table"),
            "relation_type": "table",
            "relation_name_storage_class": "text",
            "relation_name_hex": hex(child),
            "owner_name_storage_class": "not_applicable",
            "owner_name_hex": "",
            "schema_sql_storage_class": "not_applicable",
            "table_sql_token_source_is_null": 1,
            "table_sql_token_source_hex": "",
            "table_virtual_token_hit": 0,
            "foreign_key_id_storage_class": "integer",
            "foreign_key_id_value_hex": hex(&id.to_string()),
            "foreign_key_id": id,
            "foreign_key_seq_storage_class": "integer",
            "foreign_key_seq_value_hex": hex(&seq.to_string()),
            "foreign_key_seq": seq,
            "parent_name_storage_class": "text",
            "parent_name_hex": hex(parent),
            "from_column_storage_class": "text",
            "from_column_hex": hex(from_column),
            "to_column_storage_class": if to_column.is_some() { "text" } else { "null" },
            "to_column_is_null": u8::from(to_column.is_none()),
            "to_column_hex": to_column.map(hex).unwrap_or_default(),
            "on_update_storage_class": "text",
            "on_update_hex": hex(on_update),
            "on_delete_storage_class": "text",
            "on_delete_hex": hex(on_delete),
            "match_storage_class": "text",
            "match_hex": hex(match_mode),
            "conservative_blocker": if parent_resolved { "" } else { "foreign_key_parent_unresolved" },
        })
    }

    fn malformed_schema_row(
        schema_rowid: i64,
        type_storage: &str,
        type_value_hex: &str,
        name_storage: &str,
        name_hex: &str,
        owner_storage: &str,
        owner_hex: &str,
        sql_storage: &str,
        blocker: &str,
    ) -> Value {
        let mut value = json!({
            "schema_rowid": schema_rowid,
            "fact_order": 0,
            "fact_kind": "schema_blocker",
            "relation_type_storage_class": type_storage,
            "relation_type_value_hex": type_value_hex,
            "relation_type": if type_storage == "text" && type_value_hex == hex("table") { "table" } else { "" },
            "relation_name_storage_class": name_storage,
            "relation_name_hex": name_hex,
            "owner_name_storage_class": owner_storage,
            "owner_name_hex": owner_hex,
            "schema_sql_storage_class": sql_storage,
            "table_sql_token_source_is_null": 1,
            "table_sql_token_source_hex": "",
            "table_virtual_token_hit": 0,
            "conservative_blocker": blocker,
        });
        value
            .as_object_mut()
            .expect("malformed schema row")
            .extend(schema_sentinels().as_object().expect("sentinels").clone());
        value
    }

    fn hex(value: &str) -> String {
        value
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect()
    }

    fn execute_fixed_query(setup: &str) -> Option<Vec<D1CatalogProjectionRow>> {
        let mut child = match Command::new("sqlite3")
            .args(["-json", ":memory:"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => panic!("sqlite3 fixture failed to start: {error}"),
        };
        let input = format!(
            ".dbconfig defensive off\n{setup}\nPRAGMA writable_schema=ON;\n{D1_CATALOG_QUERY};\n"
        );
        child
            .stdin
            .take()
            .expect("sqlite stdin")
            .write_all(input.as_bytes())
            .expect("write sqlite fixture");
        let output = child.wait_with_output().expect("sqlite fixture output");
        assert!(
            output.status.success(),
            "sqlite fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json_start = output
            .stdout
            .iter()
            .position(|byte| *byte == b'[')
            .expect("sqlite JSON array");
        Some(
            serde_json::from_slice(&output.stdout[json_start..])
                .expect("exact fixed-query JSON rows"),
        )
    }

    fn payload(rows: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": 4,
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
        assert_eq!(plan.version, 4);
        assert_eq!(plan.projection_version, 4);
        assert_eq!(
            plan.projection_fields,
            [
                "schema_rowid",
                "fact_order",
                "fact_kind",
                "relation_type_storage_class",
                "relation_type_value_hex",
                "relation_type",
                "relation_name_storage_class",
                "relation_name_hex",
                "owner_name_storage_class",
                "owner_name_hex",
                "schema_sql_storage_class",
                "table_sql_token_source_is_null",
                "table_sql_token_source_hex",
                "table_virtual_token_hit",
                "foreign_key_id_storage_class",
                "foreign_key_id_value_hex",
                "foreign_key_id",
                "foreign_key_seq_storage_class",
                "foreign_key_seq_value_hex",
                "foreign_key_seq",
                "parent_name_storage_class",
                "parent_name_hex",
                "from_column_storage_class",
                "from_column_hex",
                "to_column_storage_class",
                "to_column_is_null",
                "to_column_hex",
                "on_update_storage_class",
                "on_update_hex",
                "on_delete_storage_class",
                "on_delete_hex",
                "match_storage_class",
                "match_hex",
                "conservative_blocker",
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
    fn fixed_query_executes_complete_sqlite_metadata_projection() {
        let setup = r#"
CREATE TABLE parent(x INTEGER, y INTEGER, "" INTEGER, PRIMARY KEY(x,y));
CREATE TABLE child(a INTEGER, b INTEGER,
  FOREIGN KEY(a,b) REFERENCES parent(x,y) MATCH FULL
  ON UPDATE RESTRICT ON DELETE SET DEFAULT);
CREATE TABLE implicit_target(a INTEGER REFERENCES parent);
CREATE TABLE empty_target(a INTEGER REFERENCES parent(""));
CREATE VIEW child_view AS SELECT a FROM child;
CREATE INDEX child_a_idx ON child(a);
CREATE TRIGGER child_ai AFTER INSERT ON child BEGIN SELECT NEW.a; END;
CREATE TABLE type_blob(id);
CREATE TABLE name_blob(id);
CREATE TABLE owner_blob(id);
CREATE TABLE sql_blob(id);
PRAGMA writable_schema=ON;
UPDATE sqlite_schema SET type=CAST(type AS BLOB) WHERE name='type_blob';
UPDATE sqlite_schema SET name=CAST(name AS BLOB) WHERE name='name_blob';
UPDATE sqlite_schema SET tbl_name=CAST(tbl_name AS BLOB) WHERE name='owner_blob';
UPDATE sqlite_schema SET sql=CAST(sql AS BLOB) WHERE name='sql_blob';
"#;
        let Some(rows) = execute_fixed_query(setup) else {
            return;
        };
        validate_projection_rows(&rows).expect("exact SQLite projection");
        let foreign_keys = rows
            .iter()
            .filter(|row| row.fact_kind == "foreign_key")
            .collect::<Vec<_>>();
        assert_eq!(foreign_keys.len(), 4);
        assert!(foreign_keys.iter().any(|row| {
            row.foreign_key_seq == 1
                && row.from_column_hex == hex("b")
                && row.to_column_hex == hex("y")
        }));
        assert!(foreign_keys.iter().any(|row| {
            row.to_column_storage_class == "null"
                && row.to_column_is_null == 1
                && row.to_column_hex.is_empty()
        }));
        assert!(foreign_keys.iter().any(|row| {
            row.to_column_storage_class == "text"
                && row.to_column_is_null == 0
                && row.to_column_hex.is_empty()
        }));
        assert!(foreign_keys.iter().all(|row| row.match_hex == hex("NONE")));
        for blocker in [
            "schema_type_storage_class_invalid",
            "schema_name_storage_class_invalid",
            "schema_owner_storage_class_invalid",
            "schema_sql_storage_class_invalid",
        ] {
            assert!(
                rows.iter().any(|row| row.conservative_blocker == blocker),
                "missing blocker {blocker}"
            );
        }
    }

    #[test]
    fn fixed_query_preserves_bounded_virtual_table_and_shadow_evidence() {
        let setup = r#"
CREATE TABLE ledger(id INTEGER PRIMARY KEY);
CREATE VIRTUAL TABLE documents USING fts5(body);
"#;
        let Some(rows) = execute_fixed_query(setup) else {
            return;
        };
        validate_projection_rows(&rows).expect("virtual catalog projection is internally exact");

        let virtual_relation = rows
            .iter()
            .find(|row| row.fact_kind == "relation" && row.relation_name_hex == hex("documents"))
            .expect("FTS5 virtual relation");
        assert_eq!(virtual_relation.relation_type, "table");
        assert_eq!(virtual_relation.table_virtual_token_hit, 1);
        assert_eq!(
            virtual_relation.conservative_blocker,
            "table_virtual_semantics_unproven"
        );
        for shadow_name in [
            "documents_data",
            "documents_idx",
            "documents_content",
            "documents_docsize",
            "documents_config",
        ] {
            assert!(
                rows.iter().any(|row| {
                    row.fact_kind == "relation" && row.relation_name_hex == hex(shadow_name)
                }),
                "missing physical FTS5 shadow table {shadow_name}"
            );
        }

        let mut contradictory = virtual_relation.clone();
        contradictory.table_virtual_token_hit = 0;
        let mut contradictory_rows = rows.clone();
        let position = contradictory_rows
            .iter()
            .position(|row| row.schema_rowid == contradictory.schema_rowid && row.fact_order == 0)
            .expect("virtual row position");
        contradictory_rows[position] = contradictory;
        contradictory_rows.sort();
        assert_eq!(
            validate_projection_rows(&contradictory_rows)
                .expect_err("virtual evidence bit cannot drift from retained bytes")
                .classification,
            D1CatalogEvidenceClassification::CatalogFactsContradictory
        );
    }

    #[test]
    fn oversized_table_token_sources_are_explicit_blockers() {
        let oversized = format!(
            "CREATE TABLE oversized(value TEXT /* {} */)",
            "x".repeat(D1_CATALOG_TABLE_SQL_TOKEN_SOURCE_BYTE_CAP)
        );
        let oversized_row: D1CatalogProjectionRow =
            serde_json::from_value(row(1, "oversized", Some(&oversized))).expect("typed row");
        assert_eq!(oversized_row.table_virtual_token_hit, 0);
        assert_eq!(
            oversized_row.conservative_blocker,
            "table_sql_token_source_oversized"
        );
        validate_projection_rows(&[oversized_row]).expect("oversized evidence is exact blocker");
    }

    #[test]
    fn fixed_query_keeps_late_malformed_row_as_sentinel() {
        let mut setup = String::new();
        for index in 0..=1_000 {
            setup.push_str(&format!("CREATE TABLE table_{index:04}(id);\n"));
        }
        setup.push_str(
            "PRAGMA writable_schema=ON;\nUPDATE sqlite_schema SET type=CAST(type AS BLOB) WHERE name='table_1000';\n",
        );
        let Some(rows) = execute_fixed_query(&setup) else {
            return;
        };
        assert_eq!(rows.len(), D1_CATALOG_PROVIDER_ROW_CAP);
        assert_eq!(rows.last().expect("sentinel").fact_kind, "schema_blocker");
        assert_eq!(
            rows.last().expect("sentinel").conservative_blocker,
            "schema_type_storage_class_invalid"
        );
    }

    #[test]
    fn stable_independent_primary_complete_observations_produce_aggregate_receipt() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let body = payload(vec![row(
            1,
            "alpha",
            Some("CREATE TABLE alpha (id INTEGER)"),
        )]);
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
        assert_eq!(receipt.schema_physical_row_count, 1);
        assert_eq!(receipt.relation_fact_count, 1);
        assert_eq!(receipt.trigger_owner_fact_count, 0);
        assert_eq!(receipt.schema_auxiliary_fact_count, 0);
        assert_eq!(receipt.schema_blocker_fact_count, 0);
        assert_eq!(receipt.foreign_key_fact_count, 0);
        assert_eq!(receipt.foreign_key_blocker_fact_count, 0);
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
            br#"{"version":3,"meta":{"query_succeeded":true,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0},"rows":[]}"#.to_vec(),
            br#"{"version":3,"results_truncated":"false","meta":{"query_succeeded":true,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0},"rows":[]}"#.to_vec(),
            br#"{"version":3,"results_truncated":false,"results_truncated":false,"meta":{"query_succeeded":true,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0},"rows":[]}"#.to_vec(),
            br#"{"version":3,"results_truncated":false,"meta":{"query_succeeded":true,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0},"rows":[],"arbitrary":true}"#.to_vec(),
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
            row(
                1,
                "child",
                Some("CREATE TABLE child(parent_id REFERENCES parent(id))"),
            ),
            foreign_key(
                1,
                "child",
                "parent",
                0,
                0,
                "parent_id",
                Some("id"),
                "SET NULL",
                "CASCADE",
                "NONE",
                true,
            ),
            row(
                2,
                "parent",
                Some("CREATE TABLE parent(id INTEGER PRIMARY KEY)"),
            ),
            view(3, "parent_view"),
            trigger(4, "child_after_insert", "child", true),
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
    fn foreign_key_columns_match_and_null_empty_distinctions_are_exact() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let rows = vec![
            row(1, "child", Some("CREATE TABLE child(a,b)")),
            foreign_key(
                1,
                "child",
                "parent",
                0,
                0,
                "left_from",
                None,
                "RESTRICT",
                "SET DEFAULT",
                "FULL",
                true,
            ),
            foreign_key(
                1,
                "child",
                "parent",
                0,
                1,
                "right_from",
                Some(""),
                "RESTRICT",
                "SET DEFAULT",
                "FULL",
                true,
            ),
            row(2, "parent", Some("CREATE TABLE parent(x,y)")),
        ];
        let body = payload(rows.clone());
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
            .expect("complete composite foreign key");
        let foreign_keys = product
            .rows()
            .iter()
            .filter(|row| row.fact_kind == "foreign_key")
            .collect::<Vec<_>>();
        assert_eq!(foreign_keys.len(), 2);
        assert_eq!(foreign_keys[0].from_column_hex, hex("left_from"));
        assert_eq!(foreign_keys[0].to_column_storage_class, "null");
        assert_eq!(foreign_keys[0].to_column_is_null, 1);
        assert_eq!(foreign_keys[1].from_column_hex, hex("right_from"));
        assert_eq!(foreign_keys[1].to_column_storage_class, "text");
        assert_eq!(foreign_keys[1].to_column_is_null, 0);
        assert_eq!(foreign_keys[1].to_column_hex, "");
        assert_eq!(foreign_keys[0].match_hex, hex("FULL"));

        let mut changed_rows = rows;
        changed_rows[1]["match_hex"] = json!(hex("NONE"));
        changed_rows[2]["match_hex"] = json!(hex("NONE"));
        let changed = payload(changed_rows);
        let changed_second = frame(
            &target,
            &plan_sha256,
            "dispatch-second-001",
            "read-second-0000001",
            &changed,
        );
        assert_eq!(
            classification(&plan, &plan_sha256, &first, &changed_second),
            D1CatalogEvidenceClassification::CatalogSnapshotsUnstable
        );
    }

    #[test]
    fn non_text_schema_storage_classes_are_preserved_as_blocker_rows() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let body = payload(vec![
            malformed_schema_row(
                1,
                "blob",
                &hex("table"),
                "text",
                &hex("type_blob"),
                "text",
                &hex("type_blob"),
                "text",
                "schema_type_storage_class_invalid",
            ),
            malformed_schema_row(
                2,
                "text",
                &hex("table"),
                "blob",
                &hex("name_blob"),
                "text",
                &hex("name_blob"),
                "text",
                "schema_name_storage_class_invalid",
            ),
            malformed_schema_row(
                3,
                "text",
                &hex("table"),
                "text",
                &hex("owner_integer"),
                "integer",
                &hex("7"),
                "text",
                "schema_owner_storage_class_invalid",
            ),
            malformed_schema_row(
                4,
                "text",
                &hex("table"),
                "text",
                &hex("sql_blob"),
                "text",
                &hex("sql_blob"),
                "blob",
                "schema_sql_storage_class_invalid",
            ),
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
        let receipt = prove(&plan, &plan_sha256, &first, &second).expect("typed blockers");
        assert_eq!(receipt.schema_physical_row_count, 4);
        assert_eq!(receipt.schema_blocker_fact_count, 4);
        assert_eq!(receipt.conservative_blocker_count, 4);
        assert_eq!(receipt.foreign_key_fact_count, 0);
    }

    #[test]
    fn storage_aliases_and_non_text_foreign_key_fields_fail_closed_as_facts() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let mut canonical_alias = row(1, "alias", Some("CREATE TABLE alias(id INTEGER)"));
        canonical_alias["fact_kind"] = json!("schema_blocker");
        canonical_alias["table_sql_token_source_is_null"] = json!(1);
        canonical_alias["table_sql_token_source_hex"] = json!("");
        canonical_alias["conservative_blocker"] = json!("schema_identity_ambiguous");
        let blob_alias = malformed_schema_row(
            2,
            "text",
            &hex("table"),
            "blob",
            &hex("alias"),
            "text",
            &hex("alias"),
            "text",
            "schema_name_storage_class_invalid",
        );
        let child = row(3, "child", Some("CREATE TABLE child(parent_id)"));
        let mut malformed_fk = foreign_key(
            3,
            "child",
            "alias",
            0,
            0,
            "parent_id",
            Some("id"),
            "NO ACTION",
            "CASCADE",
            "NONE",
            false,
        );
        malformed_fk["fact_kind"] = json!("foreign_key_blocker");
        malformed_fk["parent_name_storage_class"] = json!("blob");
        malformed_fk["conservative_blocker"] = json!("foreign_key_parent_storage_class_invalid");
        let body = payload(vec![canonical_alias, blob_alias, child, malformed_fk]);
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
        let receipt = prove(&plan, &plan_sha256, &first, &second).expect("explicit blockers");
        assert_eq!(receipt.schema_physical_row_count, 3);
        assert_eq!(receipt.schema_blocker_fact_count, 2);
        assert_eq!(receipt.foreign_key_blocker_fact_count, 1);
        assert_eq!(receipt.conservative_blocker_count, 3);
    }

    #[test]
    fn empty_sqlite_identifiers_remain_exact_structured_facts() {
        let target = target();
        let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
        let body = payload(vec![
            row(1, "", Some("CREATE TABLE \"\"(id INTEGER)")),
            trigger(2, "empty_owner_trigger", "", true),
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
            row(
                1,
                "child",
                Some("CREATE TABLE child(parent_id REFERENCES missing(id))"),
            ),
            foreign_key(
                1,
                "child",
                "missing",
                0,
                0,
                "parent_id",
                Some("id"),
                "NO ACTION",
                "CASCADE",
                "NONE",
                false,
            ),
            row(2, "opaque", None),
            trigger(3, "orphaned", "missing", false),
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
            row(
                1,
                "child",
                Some("CREATE TABLE child(parent_id REFERENCES missing(id))"),
            ),
            foreign_key(
                1,
                "child",
                "missing",
                0,
                0,
                "parent_id",
                Some("id"),
                "NO ACTION",
                "CASCADE",
                "NONE",
                true,
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
            row(
                1,
                "child",
                Some("CREATE TABLE child(parent_id REFERENCES parent(id))"),
            ),
            foreign_key(
                1,
                "child",
                "parent",
                0,
                1,
                "parent_id",
                Some("id"),
                "NO ACTION",
                "CASCADE",
                "NONE",
                true,
            ),
            row(
                2,
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
                    i64::from(index) + 1,
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
        sentinel_rows.push(malformed_schema_row(
            1_001,
            "blob",
            "7461626C65",
            "blob",
            "7461626C655F31303030",
            "text",
            "7461626C655F31303030",
            "blob",
            "schema_type_storage_class_invalid",
        ));
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

        let mut malformed_row = row(1, "alpha", Some("CREATE TABLE alpha(id INTEGER)"));
        malformed_row["relation_name_hex"] = json!("lowercase");
        let malformed = payload(vec![malformed_row]);
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
            row(2, "zeta", Some("CREATE TABLE zeta (id INTEGER)")),
            row(1, "alpha", Some("CREATE TABLE alpha (id INTEGER)")),
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
            1,
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
