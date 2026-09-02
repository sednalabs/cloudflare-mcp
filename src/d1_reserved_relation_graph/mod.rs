//! Pure reserved-relation write graph from verifier-accepted D1 catalog evidence.
//!
//! This boundary consumes only the opaque product issued by
//! `d1_catalog_evidence`. It parses a deliberately closed subset of catalog
//! table/view/trigger definitions, expands trigger, AUTOINCREMENT, and
//! operation-specific foreign-key write edges, and computes every relation /
//! operation decision under bounded cycle-safe traversal. It owns no caller
//! DML composition, provider I/O, mutation custody, public route, or execution.

mod graph;
mod lexer;
mod schema;
mod trigger;

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::d1_catalog_evidence::D1VerifiedCatalogEvidence;
use graph::CatalogObject;

pub(crate) const D1_RESERVED_RELATION_GRAPH_OPERATION: &str = "d1_reserved_relation_write_graph";
const GRAPH_VERSION: u8 = 1;
const MAX_CONFIGURED_RESERVED_RELATIONS: usize = 64;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WriteOperation {
    Insert,
    Update,
    Delete,
}

impl WriteOperation {
    const ALL: [Self; 3] = [Self::Insert, Self::Update, Self::Delete];
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct WriteNode {
    relation: String,
    operation: WriteOperation,
}

impl WriteNode {
    fn new(relation: &str, operation: WriteOperation) -> Self {
        Self {
            relation: relation.to_string(),
            operation,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum GraphDecision {
    Allow,
    DenyReservedReachable,
    DenyUnsupportedView,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1ReservedRelationGraphReceipt {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) target_key_sha256: String,
    pub(crate) catalog_snapshot_sha256: String,
    pub(crate) catalog_row_count: usize,
    pub(crate) configured_reserved_relation_count: usize,
    pub(crate) total_reserved_relation_count: usize,
    pub(crate) reserved_relation_set_sha256: String,
    pub(crate) relation_count: usize,
    pub(crate) table_count: usize,
    pub(crate) view_count: usize,
    pub(crate) trigger_count: usize,
    pub(crate) graph_node_count: usize,
    pub(crate) graph_edge_count: usize,
    pub(crate) allow_count: usize,
    pub(crate) deny_reserved_reachable_count: usize,
    pub(crate) deny_unsupported_view_count: usize,
    pub(crate) graph_sha256: String,
    pub(crate) decision_sha256: String,
}

/// Opaque deterministic policy product for the later composition boundary.
/// Only its aggregate-safe receipt is serializable in this slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1ReservedRelationGraphProduct {
    pub(crate) receipt: D1ReservedRelationGraphReceipt,
    decisions: BTreeMap<WriteNode, GraphDecision>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1ReservedRelationGraphClassification {
    CatalogProductMismatch,
    CatalogTextInvalid,
    CatalogObjectUnsupported,
    CatalogObjectCollision,
    CatalogDefinitionMissing,
    CatalogDefinitionUnsupported,
    CatalogReferenceMissing,
    ReservedRelationInvalid,
    ReservedRelationDuplicate,
    ReservedRelationAbsent,
    GraphLimitExceeded,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1ReservedRelationGraphError {
    pub(crate) code: &'static str,
    pub(crate) classification: D1ReservedRelationGraphClassification,
    pub(crate) message: &'static str,
}

pub(crate) fn derive_d1_reserved_relation_graph(
    catalog: &D1VerifiedCatalogEvidence,
    configured_reserved_relations: &[String],
) -> Result<D1ReservedRelationGraphProduct, D1ReservedRelationGraphError> {
    let catalog_receipt = catalog.receipt();
    if catalog_receipt.catalog_row_count != catalog.rows().len()
        || catalog_receipt.stable_primary_observations != 2
    {
        return Err(graph_error(
            D1ReservedRelationGraphClassification::CatalogProductMismatch,
            "verified catalog product and aggregate receipt did not match",
        ));
    }
    let configured = normalize_reserved(configured_reserved_relations)?;
    let mut objects = Vec::with_capacity(catalog.rows().len());
    let mut reserved = configured.clone();
    for row in catalog.rows() {
        let name = decode_name(row.object_name_hex())?;
        let parent = decode_name(row.parent_name_hex())?;
        let identity = name.to_ascii_lowercase();
        if is_automatic_reserved(&identity) {
            reserved.insert(identity.clone());
        }
        let definition = row.definition_hex().map(decode_definition).transpose()?;
        objects.push(CatalogObject {
            object_type: row.object_type().to_string(),
            name: identity,
            parent: parent.to_ascii_lowercase(),
            definition,
        });
    }
    let built = graph::build(objects, &reserved)?;
    let allow_count = built
        .decisions
        .values()
        .filter(|decision| matches!(decision, GraphDecision::Allow))
        .count();
    let deny_reserved_reachable_count = built
        .decisions
        .values()
        .filter(|decision| matches!(decision, GraphDecision::DenyReservedReachable))
        .count();
    let deny_unsupported_view_count = built
        .decisions
        .values()
        .filter(|decision| matches!(decision, GraphDecision::DenyUnsupportedView))
        .count();
    let receipt = D1ReservedRelationGraphReceipt {
        version: GRAPH_VERSION,
        operation: D1_RESERVED_RELATION_GRAPH_OPERATION,
        target_key_sha256: catalog_receipt.target_key_sha256.clone(),
        catalog_snapshot_sha256: catalog_receipt.catalog_snapshot_sha256.clone(),
        catalog_row_count: catalog_receipt.catalog_row_count,
        configured_reserved_relation_count: configured.len(),
        total_reserved_relation_count: reserved.len(),
        reserved_relation_set_sha256: hash_serialized(&reserved),
        relation_count: built.relation_count,
        table_count: built.table_count,
        view_count: built.view_count,
        trigger_count: built.trigger_count,
        graph_node_count: built.node_count,
        graph_edge_count: built.edge_count,
        allow_count,
        deny_reserved_reachable_count,
        deny_unsupported_view_count,
        graph_sha256: built.graph_sha256,
        decision_sha256: built.decision_sha256,
    };
    Ok(D1ReservedRelationGraphProduct {
        receipt,
        decisions: built.decisions,
    })
}

fn normalize_reserved(values: &[String]) -> Result<BTreeSet<String>, D1ReservedRelationGraphError> {
    if values.is_empty() || values.len() > MAX_CONFIGURED_RESERVED_RELATIONS {
        return Err(graph_error(
            D1ReservedRelationGraphClassification::ReservedRelationInvalid,
            "configured reserved-relation set was empty or exceeded its exact bound",
        ));
    }
    let mut normalized = BTreeSet::new();
    for value in values {
        validate_name(value)?;
        let identity = value.to_ascii_lowercase();
        if is_automatic_reserved(&identity) {
            return Err(graph_error(
                D1ReservedRelationGraphClassification::ReservedRelationInvalid,
                "automatic SQLite and Cloudflare reserved families cannot be configured aliases",
            ));
        }
        if !normalized.insert(identity) {
            return Err(graph_error(
                D1ReservedRelationGraphClassification::ReservedRelationDuplicate,
                "configured reserved relations collided under SQLite ASCII identity",
            ));
        }
    }
    Ok(normalized)
}

fn decode_name(value: &str) -> Result<String, D1ReservedRelationGraphError> {
    let bytes = decode_hex(value)?;
    let value = String::from_utf8(bytes).map_err(|_| invalid_catalog_text())?;
    validate_name(&value)?;
    Ok(value)
}

fn decode_definition(value: &str) -> Result<String, D1ReservedRelationGraphError> {
    let bytes = decode_hex(value)?;
    if bytes.is_empty() || bytes.len() > lexer::MAX_DEFINITION_BYTES {
        return Err(invalid_catalog_text());
    }
    let value = String::from_utf8(bytes).map_err(|_| invalid_catalog_text())?;
    if !value.is_ascii() || value.bytes().any(|byte| byte == 0) {
        return Err(invalid_catalog_text());
    }
    Ok(value)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, D1ReservedRelationGraphError> {
    if value.len() % 2 != 0 {
        return Err(invalid_catalog_text());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or_else(invalid_catalog_text)?;
            let low = hex_nibble(pair[1]).ok_or_else(invalid_catalog_text)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn validate_name(value: &str) -> Result<(), D1ReservedRelationGraphError> {
    if value.is_empty()
        || value.len() > 255
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(invalid_catalog_text());
    }
    Ok(())
}

fn is_automatic_reserved(identity: &str) -> bool {
    identity.starts_with("sqlite_") || identity.starts_with("_cf_")
}

fn invalid_catalog_text() -> D1ReservedRelationGraphError {
    graph_error(
        D1ReservedRelationGraphClassification::CatalogTextInvalid,
        "verified catalog bytes were not bounded canonical ASCII schema text",
    )
}

fn graph_error(
    classification: D1ReservedRelationGraphClassification,
    message: &'static str,
) -> D1ReservedRelationGraphError {
    D1ReservedRelationGraphError {
        code: "d1.reserved_relation_graph_unproven",
        classification,
        message,
    }
}

fn hash_serialized<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("graph evidence serialization");
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests;
