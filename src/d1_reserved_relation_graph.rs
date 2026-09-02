//! Conservative reserved-relation write graph from verified D1 catalog facts.
//!
//! This pure boundary accepts only the opaque version-3 catalog product. It
//! creates operation-specific foreign-key and AUTOINCREMENT edges, then derives
//! bounded cycle-safe decisions for every verified relation. Trigger bodies and
//! view definitions are deliberately unavailable: reaching a trigger-owned
//! relation or a view therefore denies rather than invoking a SQL parser.
//!
//! This module owns no caller DML composition, provider I/O, public tool route,
//! admission, custody, or mutation behavior.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::d1_catalog_evidence::{
    D1_CATALOG_EVIDENCE_OPERATION, D1CatalogEvidenceProduct, D1CatalogEvidenceReceipt,
    D1CatalogProjectionRow,
};

pub(crate) const D1_RESERVED_RELATION_GRAPH_OPERATION: &str = "d1_reserved_relation_write_graph";

const GRAPH_VERSION: u8 = 1;
const REQUIRED_CATALOG_VERSION: u8 = 3;
const MAX_CONFIGURED_RESERVED_ROOTS: usize = 64;
const MAX_RELATIONS: usize = 1_000;
const MAX_GRAPH_NODES: usize = MAX_RELATIONS * 3;
const MAX_GRAPH_EDGES: usize = 4_096;
const MAX_TABLE_TOKEN_SOURCE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1RelationWriteOperation {
    Insert,
    Update,
    Delete,
}

impl D1RelationWriteOperation {
    const ALL: [Self; 3] = [Self::Insert, Self::Update, Self::Delete];
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1ReservedRelationDecision {
    Allow,
    DenyReservedReachable,
    DenyTriggerEffectsUnproven,
    DenyViewWriteSemanticsUnproven,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct WriteNode {
    relation: String,
    operation: D1RelationWriteOperation,
}

impl WriteNode {
    fn new(relation: &str, operation: D1RelationWriteOperation) -> Self {
        Self {
            relation: relation.to_string(),
            operation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelationKind {
    Table,
    View,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Relation {
    kind: RelationKind,
    autoincrement: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForeignKeyGroup {
    child: String,
    parent: String,
    on_update: String,
    on_delete: String,
    match_mode: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1ReservedRelationGraphReceipt {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) target_key_sha256: String,
    pub(crate) catalog_snapshot_sha256: String,
    pub(crate) catalog_projection_version: u8,
    pub(crate) catalog_row_count: usize,
    pub(crate) configured_reserved_root_count: usize,
    pub(crate) automatic_reserved_root_count: usize,
    pub(crate) total_reserved_root_count: usize,
    pub(crate) reserved_root_set_sha256: String,
    pub(crate) relation_count: usize,
    pub(crate) table_count: usize,
    pub(crate) view_count: usize,
    pub(crate) trigger_fact_count: usize,
    pub(crate) trigger_owned_relation_count: usize,
    pub(crate) schema_auxiliary_fact_count: usize,
    pub(crate) foreign_key_fact_count: usize,
    pub(crate) foreign_key_group_count: usize,
    pub(crate) autoincrement_relation_count: usize,
    pub(crate) graph_node_count: usize,
    pub(crate) graph_edge_count: usize,
    pub(crate) allow_count: usize,
    pub(crate) deny_reserved_reachable_count: usize,
    pub(crate) deny_trigger_effects_unproven_count: usize,
    pub(crate) deny_view_write_semantics_unproven_count: usize,
    pub(crate) graph_sha256: String,
    pub(crate) decision_sha256: String,
}

/// Opaque internal decision product. Only its aggregate-safe receipt is
/// serializable; relation identities remain inside this later-consumer seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1ReservedRelationGraphProduct {
    receipt: D1ReservedRelationGraphReceipt,
    decisions: BTreeMap<WriteNode, D1ReservedRelationDecision>,
}

impl D1ReservedRelationGraphProduct {
    pub(crate) fn receipt(&self) -> &D1ReservedRelationGraphReceipt {
        &self.receipt
    }

    pub(crate) fn decision_for(
        &self,
        relation: &str,
        operation: D1RelationWriteOperation,
    ) -> Option<D1ReservedRelationDecision> {
        let identity = canonical_identity(relation).ok()?;
        self.decisions
            .get(&WriteNode::new(&identity, operation))
            .copied()
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1ReservedRelationGraphClassification {
    CatalogProductMismatch,
    CatalogProjectionUnsupported,
    CatalogFactBlocked,
    CatalogFactUnsupported,
    CatalogTextInvalid,
    CatalogReferenceMissing,
    ReservedRootInvalid,
    ReservedRootDuplicate,
    ReservedRootAbsent,
    AutoincrementEvidenceUnsupported,
    GraphLimitExceeded,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1ReservedRelationGraphError {
    pub(crate) code: &'static str,
    pub(crate) classification: D1ReservedRelationGraphClassification,
    pub(crate) message: &'static str,
}

pub(crate) fn derive_d1_reserved_relation_graph(
    catalog: &D1CatalogEvidenceProduct,
    configured_reserved_roots: &[String],
) -> Result<D1ReservedRelationGraphProduct, D1ReservedRelationGraphError> {
    derive_from_verified_parts(catalog.receipt(), catalog.rows(), configured_reserved_roots)
}

fn derive_from_verified_parts(
    catalog_receipt: &D1CatalogEvidenceReceipt,
    rows: &[D1CatalogProjectionRow],
    configured_reserved_roots: &[String],
) -> Result<D1ReservedRelationGraphProduct, D1ReservedRelationGraphError> {
    validate_catalog_product(catalog_receipt, rows)?;
    let configured_reserved = normalize_reserved_roots(configured_reserved_roots)?;

    let mut relations = BTreeMap::new();
    let mut trigger_owners = Vec::new();
    let mut auxiliary_owners = Vec::new();
    let mut foreign_keys = BTreeMap::new();
    let mut trigger_fact_count = 0usize;
    let mut schema_auxiliary_fact_count = 0usize;
    let mut foreign_key_fact_count = 0usize;

    for row in rows {
        match row.fact_kind.as_str() {
            "relation" => {
                let identity = identity_from_hex(&row.relation_name_hex, true)?;
                let relation = match row.relation_type.as_str() {
                    "table" => {
                        if !row.conservative_blocker.is_empty() {
                            return Err(blocked_fact());
                        }
                        let source = table_token_source(row)?;
                        Relation {
                            kind: RelationKind::Table,
                            autoincrement: contains_autoincrement_token(source),
                        }
                    }
                    "view" => {
                        if row.conservative_blocker != "view_write_semantics_unproven" {
                            return Err(unsupported_fact());
                        }
                        Relation {
                            kind: RelationKind::View,
                            autoincrement: false,
                        }
                    }
                    _ => return Err(unsupported_fact()),
                };
                if relations.insert(identity, relation).is_some() {
                    return Err(unsupported_fact());
                }
            }
            "trigger_owner" => {
                if row.relation_type != "trigger"
                    || row.conservative_blocker != "trigger_effects_unproven"
                {
                    return Err(unsupported_fact());
                }
                trigger_owners.push(identity_from_hex(&row.owner_name_hex, true)?);
                trigger_fact_count = checked_increment(trigger_fact_count)?;
            }
            "schema_auxiliary" => {
                if row.relation_type != "index" || !row.conservative_blocker.is_empty() {
                    return Err(unsupported_fact());
                }
                auxiliary_owners.push(identity_from_hex(&row.owner_name_hex, true)?);
                schema_auxiliary_fact_count = checked_increment(schema_auxiliary_fact_count)?;
            }
            "foreign_key" => {
                if !row.conservative_blocker.is_empty() {
                    return Err(blocked_fact());
                }
                let child = identity_from_hex(&row.relation_name_hex, true)?;
                let parent = identity_from_hex(&row.parent_name_hex, true)?;
                let group = ForeignKeyGroup {
                    child: child.clone(),
                    parent,
                    on_update: exact_text_from_hex(&row.on_update_hex)?,
                    on_delete: exact_text_from_hex(&row.on_delete_hex)?,
                    match_mode: exact_text_from_hex(&row.match_hex)?,
                };
                let key = (child, row.foreign_key_id);
                if let Some(incumbent) = foreign_keys.get(&key) {
                    if incumbent != &group {
                        return Err(unsupported_fact());
                    }
                } else {
                    foreign_keys.insert(key, group);
                }
                foreign_key_fact_count = checked_increment(foreign_key_fact_count)?;
            }
            "schema_blocker" | "foreign_key_blocker" => return Err(blocked_fact()),
            _ => return Err(unsupported_fact()),
        }
    }

    if relations.is_empty() || relations.len() > MAX_RELATIONS {
        return Err(graph_limit());
    }
    for owner in auxiliary_owners {
        if !relations.contains_key(&owner) {
            return Err(missing_reference());
        }
    }
    let trigger_owned_relations = trigger_owners
        .into_iter()
        .map(|owner| {
            if relations.contains_key(&owner) {
                Ok(owner)
            } else {
                Err(missing_reference())
            }
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    let automatic_reserved = relations
        .keys()
        .filter(|identity| is_automatic_reserved(identity))
        .cloned()
        .collect::<BTreeSet<_>>();
    for root in &configured_reserved {
        if !relations.contains_key(root) {
            return Err(graph_error(
                D1ReservedRelationGraphClassification::ReservedRootAbsent,
                "a configured reserved root was absent from verified relation facts",
            ));
        }
    }
    let reserved_roots = configured_reserved
        .union(&automatic_reserved)
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut edges = BTreeMap::new();
    for relation in relations.keys() {
        for operation in D1RelationWriteOperation::ALL {
            edges.insert(WriteNode::new(relation, operation), BTreeSet::new());
        }
    }
    if edges.len() > MAX_GRAPH_NODES {
        return Err(graph_limit());
    }

    let mut edge_count = 0usize;
    let autoincrement_relations = relations
        .iter()
        .filter_map(|(identity, relation)| relation.autoincrement.then_some(identity.clone()))
        .collect::<BTreeSet<_>>();
    if !autoincrement_relations.is_empty() {
        if relations
            .get("sqlite_sequence")
            .map(|relation| relation.kind)
            != Some(RelationKind::Table)
        {
            return Err(graph_error(
                D1ReservedRelationGraphClassification::AutoincrementEvidenceUnsupported,
                "AUTOINCREMENT evidence lacked one physical sqlite_sequence table",
            ));
        }
        for relation in &autoincrement_relations {
            add_edge(
                &mut edges,
                &mut edge_count,
                WriteNode::new(relation, D1RelationWriteOperation::Insert),
                WriteNode::new("sqlite_sequence", D1RelationWriteOperation::Update),
            )?;
        }
    }

    for foreign_key in foreign_keys.values() {
        if relations
            .get(&foreign_key.child)
            .map(|relation| relation.kind)
            != Some(RelationKind::Table)
            || relations
                .get(&foreign_key.parent)
                .map(|relation| relation.kind)
                != Some(RelationKind::Table)
            || !matches!(
                foreign_key.match_mode.as_str(),
                "NONE" | "SIMPLE" | "PARTIAL" | "FULL"
            )
        {
            return Err(missing_reference());
        }
        add_foreign_key_action(
            &mut edges,
            &mut edge_count,
            foreign_key,
            D1RelationWriteOperation::Update,
            &foreign_key.on_update,
        )?;
        add_foreign_key_action(
            &mut edges,
            &mut edge_count,
            foreign_key,
            D1RelationWriteOperation::Delete,
            &foreign_key.on_delete,
        )?;
    }

    let view_relations = relations
        .iter()
        .filter_map(|(identity, relation)| {
            (relation.kind == RelationKind::View).then_some(identity.clone())
        })
        .collect::<BTreeSet<_>>();
    let mut decisions = BTreeMap::new();
    for node in edges.keys() {
        decisions.insert(
            node.clone(),
            traverse(
                node,
                &edges,
                &reserved_roots,
                &trigger_owned_relations,
                &view_relations,
            )?,
        );
    }

    let allow_count = decision_count(&decisions, D1ReservedRelationDecision::Allow);
    let deny_reserved_reachable_count = decision_count(
        &decisions,
        D1ReservedRelationDecision::DenyReservedReachable,
    );
    let deny_trigger_effects_unproven_count = decision_count(
        &decisions,
        D1ReservedRelationDecision::DenyTriggerEffectsUnproven,
    );
    let deny_view_write_semantics_unproven_count = decision_count(
        &decisions,
        D1ReservedRelationDecision::DenyViewWriteSemanticsUnproven,
    );
    let serialized_edges = edges
        .iter()
        .map(|(source, targets)| (source, targets.iter().collect::<Vec<_>>()))
        .collect::<Vec<_>>();
    let serialized_decisions = decisions.iter().collect::<Vec<_>>();
    let graph_sha256 =
        hash_serialized(&(serialized_edges, &trigger_owned_relations, &view_relations));
    let decision_sha256 = hash_serialized(&serialized_decisions);
    let table_count = relations
        .values()
        .filter(|relation| relation.kind == RelationKind::Table)
        .count();

    let receipt = D1ReservedRelationGraphReceipt {
        version: GRAPH_VERSION,
        operation: D1_RESERVED_RELATION_GRAPH_OPERATION,
        target_key_sha256: catalog_receipt.target_key_sha256.clone(),
        catalog_snapshot_sha256: catalog_receipt.catalog_snapshot_sha256.clone(),
        catalog_projection_version: catalog_receipt.projection_version,
        catalog_row_count: catalog_receipt.catalog_row_count,
        configured_reserved_root_count: configured_reserved.len(),
        automatic_reserved_root_count: automatic_reserved.len(),
        total_reserved_root_count: reserved_roots.len(),
        reserved_root_set_sha256: hash_serialized(&reserved_roots),
        relation_count: relations.len(),
        table_count,
        view_count: relations.len() - table_count,
        trigger_fact_count,
        trigger_owned_relation_count: trigger_owned_relations.len(),
        schema_auxiliary_fact_count,
        foreign_key_fact_count,
        foreign_key_group_count: foreign_keys.len(),
        autoincrement_relation_count: autoincrement_relations.len(),
        graph_node_count: edges.len(),
        graph_edge_count: edge_count,
        allow_count,
        deny_reserved_reachable_count,
        deny_trigger_effects_unproven_count,
        deny_view_write_semantics_unproven_count,
        graph_sha256,
        decision_sha256,
    };
    Ok(D1ReservedRelationGraphProduct { receipt, decisions })
}

fn validate_catalog_product(
    receipt: &D1CatalogEvidenceReceipt,
    rows: &[D1CatalogProjectionRow],
) -> Result<(), D1ReservedRelationGraphError> {
    if receipt.version != REQUIRED_CATALOG_VERSION
        || receipt.operation != D1_CATALOG_EVIDENCE_OPERATION
        || receipt.projection_version != REQUIRED_CATALOG_VERSION
    {
        return Err(graph_error(
            D1ReservedRelationGraphClassification::CatalogProjectionUnsupported,
            "reserved graph requires the exact structured catalog projection version",
        ));
    }
    let relation_count = rows
        .iter()
        .filter(|row| row.fact_kind == "relation")
        .count();
    let trigger_count = rows
        .iter()
        .filter(|row| row.fact_kind == "trigger_owner")
        .count();
    let auxiliary_count = rows
        .iter()
        .filter(|row| row.fact_kind == "schema_auxiliary")
        .count();
    let schema_blocker_count = rows
        .iter()
        .filter(|row| row.fact_kind == "schema_blocker")
        .count();
    let foreign_key_count = rows
        .iter()
        .filter(|row| row.fact_kind == "foreign_key")
        .count();
    let foreign_key_blocker_count = rows
        .iter()
        .filter(|row| row.fact_kind == "foreign_key_blocker")
        .count();
    let schema_physical_count = rows.iter().filter(|row| row.fact_order == 0).count();
    let blocker_count = rows
        .iter()
        .filter(|row| !row.conservative_blocker.is_empty())
        .count();
    if receipt.catalog_row_count != rows.len()
        || receipt.schema_physical_row_count != schema_physical_count
        || receipt.relation_fact_count != relation_count
        || receipt.trigger_owner_fact_count != trigger_count
        || receipt.schema_auxiliary_fact_count != auxiliary_count
        || receipt.schema_blocker_fact_count != schema_blocker_count
        || receipt.foreign_key_fact_count != foreign_key_count
        || receipt.foreign_key_blocker_fact_count != foreign_key_blocker_count
        || receipt.conservative_blocker_count != blocker_count
        || receipt.stable_primary_observations != 2
    {
        return Err(graph_error(
            D1ReservedRelationGraphClassification::CatalogProductMismatch,
            "verified catalog rows and aggregate receipt did not match",
        ));
    }
    Ok(())
}

fn normalize_reserved_roots(
    values: &[String],
) -> Result<BTreeSet<String>, D1ReservedRelationGraphError> {
    if values.is_empty() || values.len() > MAX_CONFIGURED_RESERVED_ROOTS {
        return Err(graph_error(
            D1ReservedRelationGraphClassification::ReservedRootInvalid,
            "configured reserved-root set was empty or exceeded its exact bound",
        ));
    }
    let mut roots = BTreeSet::new();
    for value in values {
        let identity = canonical_identity(value).map_err(|_| {
            graph_error(
                D1ReservedRelationGraphClassification::ReservedRootInvalid,
                "a configured reserved root was not canonical bounded ASCII",
            )
        })?;
        if identity.is_empty() || is_automatic_reserved(&identity) {
            return Err(graph_error(
                D1ReservedRelationGraphClassification::ReservedRootInvalid,
                "automatic reserved families cannot be configured aliases",
            ));
        }
        if !roots.insert(identity) {
            return Err(graph_error(
                D1ReservedRelationGraphClassification::ReservedRootDuplicate,
                "configured reserved roots collided under SQLite ASCII identity",
            ));
        }
    }
    Ok(roots)
}

fn table_token_source(
    row: &D1CatalogProjectionRow,
) -> Result<Vec<u8>, D1ReservedRelationGraphError> {
    if row.schema_sql_storage_class != "text"
        || row.table_sql_token_source_is_null != 0
        || row.table_sql_token_source_hex.is_empty()
    {
        return Err(blocked_fact());
    }
    let source = decode_upper_hex(&row.table_sql_token_source_hex)?;
    if source.len() > MAX_TABLE_TOKEN_SOURCE_BYTES {
        return Err(graph_error(
            D1ReservedRelationGraphClassification::AutoincrementEvidenceUnsupported,
            "table token source exceeded the exact local classification bound",
        ));
    }
    Ok(source)
}

fn contains_autoincrement_token(source: Vec<u8>) -> bool {
    const TOKEN: &[u8] = b"AUTOINCREMENT";
    source.windows(TOKEN.len()).any(|window| {
        window
            .iter()
            .zip(TOKEN)
            .all(|(actual, expected)| actual.to_ascii_uppercase() == *expected)
    })
}

fn add_foreign_key_action(
    edges: &mut BTreeMap<WriteNode, BTreeSet<WriteNode>>,
    edge_count: &mut usize,
    foreign_key: &ForeignKeyGroup,
    parent_operation: D1RelationWriteOperation,
    action: &str,
) -> Result<(), D1ReservedRelationGraphError> {
    let child_operation = match action {
        "NO ACTION" | "RESTRICT" => None,
        "CASCADE" => Some(parent_operation),
        "SET NULL" | "SET DEFAULT" => Some(D1RelationWriteOperation::Update),
        _ => return Err(unsupported_fact()),
    };
    if let Some(child_operation) = child_operation {
        add_edge(
            edges,
            edge_count,
            WriteNode::new(&foreign_key.parent, parent_operation),
            WriteNode::new(&foreign_key.child, child_operation),
        )?;
    }
    Ok(())
}

fn add_edge(
    edges: &mut BTreeMap<WriteNode, BTreeSet<WriteNode>>,
    edge_count: &mut usize,
    source: WriteNode,
    target: WriteNode,
) -> Result<(), D1ReservedRelationGraphError> {
    if !edges.contains_key(&source) || !edges.contains_key(&target) {
        return Err(missing_reference());
    }
    if edges
        .get_mut(&source)
        .expect("checked graph node")
        .insert(target)
    {
        *edge_count = checked_increment(*edge_count)?;
        if *edge_count > MAX_GRAPH_EDGES {
            return Err(graph_limit());
        }
    }
    Ok(())
}

fn traverse(
    start: &WriteNode,
    edges: &BTreeMap<WriteNode, BTreeSet<WriteNode>>,
    reserved_roots: &BTreeSet<String>,
    trigger_owned_relations: &BTreeSet<String>,
    view_relations: &BTreeSet<String>,
) -> Result<D1ReservedRelationDecision, D1ReservedRelationGraphError> {
    let mut queue = VecDeque::from([start.clone()]);
    let mut visited = BTreeSet::from([start.clone()]);
    let mut trigger_unproven = false;
    let mut view_unproven = false;
    while let Some(node) = queue.pop_front() {
        if reserved_roots.contains(&node.relation) {
            return Ok(D1ReservedRelationDecision::DenyReservedReachable);
        }
        trigger_unproven |= trigger_owned_relations.contains(&node.relation);
        view_unproven |= view_relations.contains(&node.relation);
        let targets = edges.get(&node).ok_or_else(missing_reference)?;
        for target in targets {
            if !edges.contains_key(target) {
                return Err(missing_reference());
            }
            if visited.insert(target.clone()) {
                if visited.len() > MAX_GRAPH_NODES || visited.len() > edges.len() {
                    return Err(graph_limit());
                }
                queue.push_back(target.clone());
            }
        }
    }
    Ok(if trigger_unproven {
        D1ReservedRelationDecision::DenyTriggerEffectsUnproven
    } else if view_unproven {
        D1ReservedRelationDecision::DenyViewWriteSemanticsUnproven
    } else {
        D1ReservedRelationDecision::Allow
    })
}

fn decision_count(
    decisions: &BTreeMap<WriteNode, D1ReservedRelationDecision>,
    expected: D1ReservedRelationDecision,
) -> usize {
    decisions
        .values()
        .filter(|decision| **decision == expected)
        .count()
}

fn canonical_identity(value: &str) -> Result<String, D1ReservedRelationGraphError> {
    let bytes = value.as_bytes();
    if bytes.len() > 255 || !bytes.iter().all(|byte| matches!(*byte, 0x20..=0x7e)) {
        return Err(invalid_catalog_text());
    }
    Ok(value.to_ascii_lowercase())
}

fn identity_from_hex(
    value: &str,
    empty_allowed: bool,
) -> Result<String, D1ReservedRelationGraphError> {
    let bytes = decode_upper_hex(value)?;
    if (!empty_allowed && bytes.is_empty())
        || bytes.len() > 255
        || !bytes.iter().all(|byte| matches!(*byte, 0x20..=0x7e))
    {
        return Err(invalid_catalog_text());
    }
    let text = String::from_utf8(bytes).map_err(|_| invalid_catalog_text())?;
    Ok(text.to_ascii_lowercase())
}

fn exact_text_from_hex(value: &str) -> Result<String, D1ReservedRelationGraphError> {
    let bytes = decode_upper_hex(value)?;
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii) {
        return Err(invalid_catalog_text());
    }
    String::from_utf8(bytes).map_err(|_| invalid_catalog_text())
}

fn decode_upper_hex(value: &str) -> Result<Vec<u8>, D1ReservedRelationGraphError> {
    if value.len() % 2 != 0 {
        return Err(invalid_catalog_text());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = upper_hex_nibble(pair[0]).ok_or_else(invalid_catalog_text)?;
            let low = upper_hex_nibble(pair[1]).ok_or_else(invalid_catalog_text)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn upper_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_automatic_reserved(identity: &str) -> bool {
    identity.starts_with("sqlite_") || identity.starts_with("_cf_")
}

fn checked_increment(value: usize) -> Result<usize, D1ReservedRelationGraphError> {
    value.checked_add(1).ok_or_else(graph_limit)
}

fn blocked_fact() -> D1ReservedRelationGraphError {
    graph_error(
        D1ReservedRelationGraphClassification::CatalogFactBlocked,
        "structured catalog contained conservative blocker evidence",
    )
}

fn unsupported_fact() -> D1ReservedRelationGraphError {
    graph_error(
        D1ReservedRelationGraphClassification::CatalogFactUnsupported,
        "structured catalog fact was unsupported by the closed graph contract",
    )
}

fn invalid_catalog_text() -> D1ReservedRelationGraphError {
    graph_error(
        D1ReservedRelationGraphClassification::CatalogTextInvalid,
        "structured catalog bytes were not bounded canonical text",
    )
}

fn missing_reference() -> D1ReservedRelationGraphError {
    graph_error(
        D1ReservedRelationGraphClassification::CatalogReferenceMissing,
        "structured graph reference was absent from the verified relation set",
    )
}

fn graph_limit() -> D1ReservedRelationGraphError {
    graph_error(
        D1ReservedRelationGraphClassification::GraphLimitExceeded,
        "reserved-relation graph exceeded an exact local bound",
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
    let bytes = serde_json::to_vec(value).expect("graph evidence serialization is infallible");
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests;
