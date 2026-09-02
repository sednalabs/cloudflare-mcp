//! Side-effect-free, exact D1 catalog observation evidence.
//!
//! This module owns one immutable catalog query/projection and verifies that two
//! adapter-issued frames claim distinct, primary-served, complete observations
//! whose canonical typed projections describe one stable snapshot for one
//! canonical D1 target. It cannot authenticate provider dispatch or response
//! EOF; that custody belongs to the internal provider adapter that constructs
//! the frames. It deliberately does not interpret DDL, triggers, foreign keys, or a
//! write graph, and it has no provider client, public tool route, custody, or
//! mutation capability.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::d1_target::{D1TargetIdentity, normalize_d1_target};

pub(crate) const D1_CATALOG_EVIDENCE_OPERATION: &str = "d1_catalog_evidence";
pub(crate) const D1_CATALOG_MAX_ROWS: usize = 1_000;
pub(crate) const D1_CATALOG_PROVIDER_ROW_CAP: usize = D1_CATALOG_MAX_ROWS + 1;
pub(crate) const D1_CATALOG_PROVIDER_BYTE_CAP: usize = 4 * 1024 * 1024;

const D1_CATALOG_PROJECTION_VERSION: u8 = 1;
const D1_CATALOG_EVIDENCE_VERSION: u8 = 1;
const D1_CATALOG_QUERY: &str = "SELECT type AS object_type, \
hex(CAST(name AS BLOB)) AS object_name_hex, \
hex(CAST(tbl_name AS BLOB)) AS parent_name_hex, \
CASE WHEN sql IS NULL THEN 1 ELSE 0 END AS definition_is_null, \
CASE WHEN sql IS NULL THEN '' ELSE hex(CAST(sql AS BLOB)) END AS definition_hex \
FROM sqlite_schema \
WHERE type IN ('table', 'view', 'trigger') \
ORDER BY type COLLATE BINARY, name COLLATE BINARY, tbl_name COLLATE BINARY, sql COLLATE BINARY \
LIMIT 1001";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1CatalogEvidencePlan {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) account_id: String,
    pub(crate) database_id: String,
    pub(crate) target_key_sha256: String,
    pub(crate) projection_version: u8,
    pub(crate) projection_fields: [&'static str; 5],
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
    pub(crate) observation_pair_sha256: String,
    pub(crate) stable_primary_observations: u8,
    pub(crate) provider_row_cap: usize,
    pub(crate) provider_byte_cap: usize,
    pub(crate) response_body_sizes: [usize; 2],
}

/// Verifier-issued catalog product for downstream side-effect-free policy.
///
/// The accepted rows stay private to this crate and are available only through
/// read-only accessors. Downstream policy therefore cannot construct this
/// product from caller JSON or a generic D1 response while the aggregate
/// receipt remains safe to serialize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1VerifiedCatalogEvidence {
    receipt: D1CatalogEvidenceReceipt,
    rows: Vec<D1CatalogProjectionRow>,
}

impl D1VerifiedCatalogEvidence {
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
    object_type: String,
    object_name_hex: String,
    parent_name_hex: String,
    definition_is_null: u8,
    definition_hex: String,
}

impl D1CatalogProjectionRow {
    pub(crate) fn object_type(&self) -> &str {
        &self.object_type
    }

    pub(crate) fn object_name_hex(&self) -> &str {
        &self.object_name_hex
    }

    pub(crate) fn parent_name_hex(&self) -> &str {
        &self.parent_name_hex
    }

    pub(crate) fn definition_hex(&self) -> Option<&str> {
        (self.definition_is_null == 0).then_some(self.definition_hex.as_str())
    }
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
            "object_type",
            "object_name_hex",
            "parent_name_hex",
            "definition_is_null",
            "definition_hex",
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

/// Verify and retain the exact accepted projection for a downstream pure
/// policy boundary. This is the only constructor for the opaque product.
pub(crate) fn prove_d1_catalog_product(
    target: &D1TargetIdentity,
    supplied_plan: &D1CatalogEvidencePlan,
    expected_plan_sha256: &str,
    first: &D1CatalogObservationFrame<'_>,
    second: &D1CatalogObservationFrame<'_>,
) -> Result<D1VerifiedCatalogEvidence, D1CatalogEvidenceError> {
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

    let receipt = D1CatalogEvidenceReceipt {
        version: D1_CATALOG_EVIDENCE_VERSION,
        operation: D1_CATALOG_EVIDENCE_OPERATION,
        target_key_sha256: derived_plan.target_key_sha256,
        query_plan_sha256: derived_plan_sha256,
        query_sha256: derived_plan.query_sha256,
        projection_version: derived_plan.projection_version,
        catalog_snapshot_sha256: hash_serialized(&first_payload.rows),
        catalog_row_count: first_payload.rows.len(),
        observation_pair_sha256: hash_serialized(&identities),
        stable_primary_observations: 2,
        provider_row_cap: derived_plan.provider_row_cap,
        provider_byte_cap: derived_plan.provider_byte_cap,
        response_body_sizes: [first.body_size_bytes, second.body_size_bytes],
    };
    Ok(D1VerifiedCatalogEvidence {
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
    let mut previous: Option<(&str, &str, &str, u8, &str)> = None;
    for row in rows {
        if !matches!(row.object_type.as_str(), "table" | "trigger" | "view")
            || !canonical_upper_hex(&row.object_name_hex, false)
            || !canonical_upper_hex(&row.parent_name_hex, false)
            || !matches!(row.definition_is_null, 0 | 1)
            || !canonical_upper_hex(&row.definition_hex, true)
            || (row.definition_is_null == 1 && !row.definition_hex.is_empty())
        {
            return Err(evidence_error(
                D1CatalogEvidenceClassification::CatalogRowMalformed,
                "catalog projection row was not canonical typed evidence",
            ));
        }
        let current = (
            row.object_type.as_str(),
            row.object_name_hex.as_str(),
            row.parent_name_hex.as_str(),
            row.definition_is_null ^ 1,
            row.definition_hex.as_str(),
        );
        if previous.is_some_and(|prior| prior >= current) {
            return Err(evidence_error(
                D1CatalogEvidenceClassification::CatalogRowsNonCanonical,
                "catalog projection rows were duplicate or outside exact query order",
            ));
        }
        previous = Some(current);
    }
    Ok(())
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
            "object_type": "table",
            "object_name_hex": hex(name),
            "parent_name_hex": hex(name),
            "definition_is_null": u8::from(definition.is_none()),
            "definition_hex": definition.map(hex).unwrap_or_default(),
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
            "version": 1,
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
        assert_eq!(plan.version, 1);
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
            br#"{"version":1,"meta":{"query_succeeded":true,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0},"rows":[]}"#.to_vec(),
            br#"{"version":1,"results_truncated":"false","meta":{"query_succeeded":true,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0},"rows":[]}"#.to_vec(),
            br#"{"version":1,"results_truncated":false,"results_truncated":false,"meta":{"query_succeeded":true,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0},"rows":[]}"#.to_vec(),
            br#"{"version":1,"results_truncated":false,"meta":{"query_succeeded":true,"served_by_primary":true,"changed_db":false,"changes":0,"rows_written":0},"rows":[],"arbitrary":true}"#.to_vec(),
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
            "object_type": "table",
            "object_name_hex": "lowercase",
            "parent_name_hex": "AA",
            "definition_is_null": 1,
            "definition_hex": "AA",
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
