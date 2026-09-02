use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::schema::{RelationKind, RelationSchema, parse_relation};
use super::trigger::{TriggerTiming, parse_trigger};
use super::{
    D1ReservedRelationGraphClassification, D1ReservedRelationGraphError, GraphDecision, WriteNode,
    WriteOperation, graph_error, hash_serialized, is_automatic_reserved,
};

const MAX_GRAPH_EDGES: usize = 20_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CatalogObject {
    pub(super) object_type: String,
    pub(super) name: String,
    pub(super) parent: String,
    pub(super) definition: Option<String>,
}

#[derive(Debug, Clone)]
struct Relation {
    schema: RelationSchema,
}

#[derive(Debug)]
pub(super) struct BuiltGraph {
    pub(super) decisions: BTreeMap<WriteNode, GraphDecision>,
    pub(super) graph_sha256: String,
    pub(super) decision_sha256: String,
    pub(super) relation_count: usize,
    pub(super) table_count: usize,
    pub(super) view_count: usize,
    pub(super) trigger_count: usize,
    pub(super) edge_count: usize,
    pub(super) node_count: usize,
}

pub(super) fn build(
    objects: Vec<CatalogObject>,
    reserved: &BTreeSet<String>,
) -> Result<BuiltGraph, D1ReservedRelationGraphError> {
    let mut relations = BTreeMap::new();
    let mut trigger_objects = Vec::new();
    let mut object_identities = BTreeSet::new();
    for object in objects {
        let object_identity = (object.object_type.clone(), object.name.clone());
        if !object_identities.insert(object_identity) {
            return Err(graph_error(
                D1ReservedRelationGraphClassification::CatalogObjectCollision,
                "catalog object identities collided under SQLite ASCII identity",
            ));
        }
        match object.object_type.as_str() {
            "table" | "view" => {
                if object.name != object.parent || relations.contains_key(&object.name) {
                    return Err(graph_error(
                        D1ReservedRelationGraphClassification::CatalogObjectCollision,
                        "catalog table and view identities did not form one closed namespace",
                    ));
                }
                let kind = if object.object_type == "table" {
                    RelationKind::Table
                } else {
                    RelationKind::View
                };
                let schema = match object.definition {
                    Some(definition) => parse_relation(kind, &object.name, &definition)?,
                    None if kind == RelationKind::Table && is_automatic_reserved(&object.name) => {
                        RelationSchema {
                            kind,
                            autoincrement: false,
                            foreign_keys: Vec::new(),
                        }
                    }
                    None => {
                        return Err(graph_error(
                            D1ReservedRelationGraphClassification::CatalogDefinitionMissing,
                            "a non-internal relation lacked exact catalog definition evidence",
                        ));
                    }
                };
                relations.insert(object.name, Relation { schema });
            }
            "trigger" => trigger_objects.push(object),
            _ => {
                return Err(graph_error(
                    D1ReservedRelationGraphClassification::CatalogObjectUnsupported,
                    "verified catalog contained an unsupported object type",
                ));
            }
        }
    }
    if relations.is_empty() {
        return Err(graph_error(
            D1ReservedRelationGraphClassification::CatalogDefinitionUnsupported,
            "verified catalog did not contain a relation graph",
        ));
    }
    for required in reserved {
        if !is_automatic_reserved(required) && !relations.contains_key(required) {
            return Err(graph_error(
                D1ReservedRelationGraphClassification::ReservedRelationAbsent,
                "a configured reserved relation was absent from verified catalog evidence",
            ));
        }
    }

    let mut triggers = Vec::new();
    for object in trigger_objects {
        let definition = object.definition.ok_or_else(|| {
            graph_error(
                D1ReservedRelationGraphClassification::CatalogDefinitionMissing,
                "a trigger lacked exact catalog definition evidence",
            )
        })?;
        let parent = relations.get(&object.parent).ok_or_else(|| {
            graph_error(
                D1ReservedRelationGraphClassification::CatalogReferenceMissing,
                "a trigger parent was absent from the verified relation set",
            )
        })?;
        let trigger = parse_trigger(&object.name, &object.parent, &definition)?;
        match (parent.schema.kind, trigger.timing) {
            (RelationKind::Table, TriggerTiming::Before | TriggerTiming::After)
            | (RelationKind::View, TriggerTiming::InsteadOf) => {}
            _ => {
                return Err(graph_error(
                    D1ReservedRelationGraphClassification::CatalogDefinitionUnsupported,
                    "trigger timing did not match its exact table or view parent",
                ));
            }
        }
        triggers.push(trigger);
    }

    let mut edges: BTreeMap<WriteNode, BTreeSet<WriteNode>> = BTreeMap::new();
    let mut edge_count = 0usize;
    let mut unsupported_views = BTreeSet::new();
    for relation in relations.keys() {
        for operation in WriteOperation::ALL {
            edges
                .entry(WriteNode::new(relation, operation))
                .or_default();
        }
    }
    for trigger in &triggers {
        let source = WriteNode::new(&trigger.parent, trigger.operation);
        for effect in &trigger.effects {
            if !relations.contains_key(&effect.relation) {
                return Err(graph_error(
                    D1ReservedRelationGraphClassification::CatalogReferenceMissing,
                    "a trigger write target was absent from the verified relation set",
                ));
            }
            for operation in &effect.operations {
                add_edge(
                    &mut edges,
                    &mut edge_count,
                    source.clone(),
                    WriteNode::new(&effect.relation, *operation),
                )?;
            }
        }
    }
    for (identity, relation) in &relations {
        if relation.schema.kind == RelationKind::View {
            for operation in WriteOperation::ALL {
                let has_instead_of = triggers.iter().any(|trigger| {
                    trigger.parent == *identity
                        && trigger.operation == operation
                        && trigger.timing == TriggerTiming::InsteadOf
                });
                if !has_instead_of {
                    unsupported_views.insert(WriteNode::new(identity, operation));
                }
            }
        }
        if relation.schema.autoincrement {
            let Some(sequence) = relations.get("sqlite_sequence") else {
                return Err(graph_error(
                    D1ReservedRelationGraphClassification::CatalogReferenceMissing,
                    "AUTOINCREMENT catalog evidence lacked sqlite_sequence",
                ));
            };
            if sequence.schema.kind != RelationKind::Table {
                return Err(graph_error(
                    D1ReservedRelationGraphClassification::CatalogDefinitionUnsupported,
                    "sqlite_sequence was not a physical table",
                ));
            }
            add_edge(
                &mut edges,
                &mut edge_count,
                WriteNode::new(identity, WriteOperation::Insert),
                WriteNode::new("sqlite_sequence", WriteOperation::Update),
            )?;
        }
        for foreign_key in &relation.schema.foreign_keys {
            let parent = relations.get(&foreign_key.parent).ok_or_else(|| {
                graph_error(
                    D1ReservedRelationGraphClassification::CatalogReferenceMissing,
                    "a foreign-key parent was absent from the verified relation set",
                )
            })?;
            if parent.schema.kind != RelationKind::Table {
                return Err(graph_error(
                    D1ReservedRelationGraphClassification::CatalogDefinitionUnsupported,
                    "a foreign key referenced a non-table relation",
                ));
            }
            for (parent_operation, action) in [
                (WriteOperation::Delete, foreign_key.on_delete),
                (WriteOperation::Update, foreign_key.on_update),
            ] {
                if let Some(child_operation) = action.child_operation(parent_operation) {
                    add_edge(
                        &mut edges,
                        &mut edge_count,
                        WriteNode::new(&foreign_key.parent, parent_operation),
                        WriteNode::new(identity, child_operation),
                    )?;
                }
            }
        }
    }

    let node_count = edges.len();
    if node_count > 3_000 || edge_count > MAX_GRAPH_EDGES {
        return Err(graph_error(
            D1ReservedRelationGraphClassification::GraphLimitExceeded,
            "reserved-relation graph exceeded its exact node or edge bound",
        ));
    }
    let mut decisions = BTreeMap::new();
    for node in edges.keys() {
        decisions.insert(
            node.clone(),
            traverse(node, &edges, reserved, &unsupported_views)?,
        );
    }
    let serialized_edges = edges
        .iter()
        .map(|(source, targets)| (source, targets.iter().collect::<Vec<_>>()))
        .collect::<Vec<_>>();
    let serialized_decisions = decisions.iter().collect::<Vec<_>>();
    let graph_sha256 = hash_serialized(&serialized_edges);
    let decision_sha256 = hash_serialized(&serialized_decisions);
    let table_count = relations
        .values()
        .filter(|relation| relation.schema.kind == RelationKind::Table)
        .count();
    let view_count = relations.len() - table_count;
    Ok(BuiltGraph {
        decisions,
        graph_sha256,
        decision_sha256,
        relation_count: relations.len(),
        table_count,
        view_count,
        trigger_count: triggers.len(),
        edge_count,
        node_count,
    })
}

fn add_edge(
    edges: &mut BTreeMap<WriteNode, BTreeSet<WriteNode>>,
    edge_count: &mut usize,
    source: WriteNode,
    target: WriteNode,
) -> Result<(), D1ReservedRelationGraphError> {
    if edges.entry(source).or_default().insert(target) {
        *edge_count = edge_count.checked_add(1).ok_or_else(|| {
            graph_error(
                D1ReservedRelationGraphClassification::GraphLimitExceeded,
                "reserved-relation graph edge count overflowed",
            )
        })?;
    }
    if *edge_count > MAX_GRAPH_EDGES {
        return Err(graph_error(
            D1ReservedRelationGraphClassification::GraphLimitExceeded,
            "reserved-relation graph exceeded its exact edge bound",
        ));
    }
    Ok(())
}

fn traverse(
    start: &WriteNode,
    edges: &BTreeMap<WriteNode, BTreeSet<WriteNode>>,
    reserved: &BTreeSet<String>,
    unsupported_views: &BTreeSet<WriteNode>,
) -> Result<GraphDecision, D1ReservedRelationGraphError> {
    let mut queue = VecDeque::from([start.clone()]);
    let mut visited = BTreeSet::from([start.clone()]);
    let mut unsupported_reached = false;
    while let Some(node) = queue.pop_front() {
        if reserved.contains(&node.relation) || is_automatic_reserved(&node.relation) {
            return Ok(GraphDecision::DenyReservedReachable);
        }
        unsupported_reached |= unsupported_views.contains(&node);
        let targets = edges.get(&node).ok_or_else(|| {
            graph_error(
                D1ReservedRelationGraphClassification::CatalogReferenceMissing,
                "graph traversal reached a node outside the verified catalog",
            )
        })?;
        for target in targets {
            if !edges.contains_key(target) {
                return Err(graph_error(
                    D1ReservedRelationGraphClassification::CatalogReferenceMissing,
                    "graph edge targeted a node outside the verified catalog",
                ));
            }
            if visited.insert(target.clone()) {
                queue.push_back(target.clone());
            }
        }
        if visited.len() > edges.len() {
            return Err(graph_error(
                D1ReservedRelationGraphClassification::GraphLimitExceeded,
                "graph traversal exceeded the exact verified node set",
            ));
        }
    }
    Ok(if unsupported_reached {
        GraphDecision::DenyUnsupportedView
    } else {
        GraphDecision::Allow
    })
}
