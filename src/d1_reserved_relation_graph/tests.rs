use serde_json::{Value, json};

use super::*;
use crate::d1_catalog_evidence::{
    D1_CATALOG_PROVIDER_BYTE_CAP, D1_CATALOG_PROVIDER_ROW_CAP, D1CatalogObservationFrame,
    D1VerifiedCatalogEvidence, derive_d1_catalog_evidence_plan, prove_d1_catalog_product,
};
use crate::d1_target::{D1TargetIdentity, normalize_d1_target};

const DATABASE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

#[derive(Clone)]
struct Row {
    object_type: &'static str,
    name: &'static str,
    parent: &'static str,
    definition: Option<&'static str>,
}

fn target() -> D1TargetIdentity {
    normalize_d1_target("acct-1", DATABASE_ID).expect("target")
}

fn table(name: &'static str, definition: &'static str) -> Row {
    Row {
        object_type: "table",
        name,
        parent: name,
        definition: Some(definition),
    }
}

fn view(name: &'static str, definition: &'static str) -> Row {
    Row {
        object_type: "view",
        name,
        parent: name,
        definition: Some(definition),
    }
}

fn trigger(name: &'static str, parent: &'static str, definition: &'static str) -> Row {
    Row {
        object_type: "trigger",
        name,
        parent,
        definition: Some(definition),
    }
}

fn verified(mut rows: Vec<Row>) -> D1VerifiedCatalogEvidence {
    rows.sort_by(|left, right| {
        (
            left.object_type,
            left.name.as_bytes(),
            left.parent.as_bytes(),
            left.definition.is_some(),
            left.definition.unwrap_or_default().as_bytes(),
        )
            .cmp(&(
                right.object_type,
                right.name.as_bytes(),
                right.parent.as_bytes(),
                right.definition.is_some(),
                right.definition.unwrap_or_default().as_bytes(),
            ))
    });
    let projected = rows
        .into_iter()
        .map(|row| {
            json!({
                "object_type": row.object_type,
                "object_name_hex": hex(row.name),
                "parent_name_hex": hex(row.parent),
                "definition_is_null": u8::from(row.definition.is_none()),
                "definition_hex": row.definition.map(hex).unwrap_or_default(),
            })
        })
        .collect::<Vec<Value>>();
    let body = serde_json::to_vec(&json!({
        "version": 1,
        "results_truncated": false,
        "meta": {
            "query_succeeded": true,
            "served_by_primary": true,
            "changed_db": false,
            "changes": 0,
            "rows_written": 0,
        },
        "rows": projected,
    }))
    .expect("payload");
    let target = target();
    let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(&target).expect("plan");
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
    prove_d1_catalog_product(&target, &plan, &plan_sha256, &first, &second)
        .expect("verified product")
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

fn hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn decision(
    product: &D1ReservedRelationGraphProduct,
    relation: &str,
    operation: WriteOperation,
) -> GraphDecision {
    *product
        .decisions
        .get(&WriteNode::new(relation, operation))
        .expect("decision")
}

fn baseline_rows() -> Vec<Row> {
    vec![
        table(
            "d1_migrations",
            "CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY, name TEXT)",
        ),
        table(
            "items",
            "CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT)",
        ),
    ]
}

#[test]
fn verifier_accepted_direct_relations_produce_aggregate_only_deterministic_product() {
    let catalog = verified(baseline_rows());
    let reserved = vec!["d1_migrations".to_string()];
    let first = derive_d1_reserved_relation_graph(&catalog, &reserved).expect("graph");
    let second = derive_d1_reserved_relation_graph(&catalog, &reserved).expect("graph replay");
    assert_eq!(first.receipt, second.receipt);
    assert_eq!(first.receipt.relation_count, 2);
    assert_eq!(first.receipt.graph_node_count, 6);
    assert_eq!(first.receipt.allow_count, 3);
    assert_eq!(first.receipt.deny_reserved_reachable_count, 3);
    assert_eq!(
        decision(&first, "items", WriteOperation::Insert),
        GraphDecision::Allow
    );
    assert_eq!(
        decision(&first, "d1_migrations", WriteOperation::Delete),
        GraphDecision::DenyReservedReachable
    );
    let encoded = serde_json::to_string(&first.receipt).expect("receipt");
    assert!(!encoded.contains("d1_migrations"));
    assert!(!encoded.contains("items"));
    assert!(!encoded.contains(DATABASE_ID));
}

#[test]
fn before_after_and_instead_of_trigger_edges_reach_reserved_relations() {
    let mut rows = baseline_rows();
    rows.extend([
        table("audit", "CREATE TABLE audit(id INTEGER PRIMARY KEY)"),
        view("item_view", "CREATE VIEW item_view AS SELECT id FROM items"),
        trigger(
            "items_after_insert",
            "items",
            "CREATE TRIGGER items_after_insert AFTER INSERT ON items BEGIN INSERT INTO audit(id) VALUES (NEW.id); END",
        ),
        trigger(
            "audit_before_insert",
            "audit",
            "CREATE TRIGGER audit_before_insert BEFORE INSERT ON audit BEGIN UPDATE d1_migrations SET name = name; END",
        ),
        trigger(
            "item_view_insert",
            "item_view",
            "CREATE TRIGGER item_view_insert INSTEAD OF INSERT ON item_view WHEN NEW.id IS NOT NULL BEGIN INSERT INTO items(id) VALUES (NEW.id); END",
        ),
    ]);
    let product =
        derive_d1_reserved_relation_graph(&verified(rows), &["d1_migrations".to_string()])
            .expect("trigger graph");
    assert_eq!(
        decision(&product, "items", WriteOperation::Insert),
        GraphDecision::DenyReservedReachable
    );
    assert_eq!(
        decision(&product, "item_view", WriteOperation::Insert),
        GraphDecision::DenyReservedReachable
    );
    assert_eq!(
        decision(&product, "item_view", WriteOperation::Update),
        GraphDecision::DenyUnsupportedView
    );
    assert_eq!(product.receipt.trigger_count, 3);
}

#[test]
fn trigger_cycles_terminate_and_preserve_safe_decisions() {
    let mut rows = baseline_rows();
    rows.push(table("other", "CREATE TABLE other(id INTEGER PRIMARY KEY)"));
    rows.extend([
        trigger(
            "items_update_other",
            "items",
            "CREATE TRIGGER items_update_other AFTER UPDATE ON items BEGIN UPDATE other SET id = id; END",
        ),
        trigger(
            "other_update_items",
            "other",
            "CREATE TRIGGER other_update_items AFTER UPDATE ON other BEGIN UPDATE items SET id = id; END",
        ),
    ]);
    let product =
        derive_d1_reserved_relation_graph(&verified(rows), &["d1_migrations".to_string()])
            .expect("cycle-safe graph");
    assert_eq!(
        decision(&product, "items", WriteOperation::Update),
        GraphDecision::Allow
    );
    assert_eq!(
        decision(&product, "other", WriteOperation::Update),
        GraphDecision::Allow
    );
    assert_eq!(product.receipt.graph_edge_count, 2);
}

#[test]
fn autoincrement_insert_reaches_sqlite_sequence_but_other_operations_do_not() {
    let mut rows = baseline_rows();
    rows.retain(|row| row.name != "items");
    rows.extend([
        table(
            "items",
            "CREATE TABLE items(id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT)",
        ),
        table("sqlite_sequence", "CREATE TABLE sqlite_sequence(name,seq)"),
    ]);
    let product =
        derive_d1_reserved_relation_graph(&verified(rows.clone()), &["d1_migrations".to_string()])
            .expect("autoincrement graph");
    assert_eq!(product.receipt.total_reserved_relation_count, 2);
    assert_eq!(
        decision(&product, "items", WriteOperation::Insert),
        GraphDecision::DenyReservedReachable
    );
    assert_eq!(
        decision(&product, "items", WriteOperation::Update),
        GraphDecision::Allow
    );

    rows.retain(|row| row.name != "sqlite_sequence");
    assert_eq!(
        derive_d1_reserved_relation_graph(&verified(rows), &["d1_migrations".to_string()])
            .expect_err("missing implicit target")
            .classification,
        D1ReservedRelationGraphClassification::CatalogReferenceMissing
    );
}

#[test]
fn foreign_key_actions_are_operation_specific_and_enter_trigger_graphs() {
    let rows = vec![
        table(
            "reserved_child",
            "CREATE TABLE reserved_child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parents(id) ON DELETE CASCADE ON UPDATE SET NULL)",
        ),
        table("parents", "CREATE TABLE parents(id INTEGER PRIMARY KEY)"),
        table("audit", "CREATE TABLE audit(id INTEGER PRIMARY KEY)"),
        trigger(
            "audit_after_update",
            "audit",
            "CREATE TRIGGER audit_after_update AFTER UPDATE ON audit BEGIN DELETE FROM reserved_child; END",
        ),
        table(
            "restricted_child",
            "CREATE TABLE restricted_child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES audit(id) ON DELETE RESTRICT ON UPDATE NO ACTION)",
        ),
    ];
    let product =
        derive_d1_reserved_relation_graph(&verified(rows), &["reserved_child".to_string()])
            .expect("foreign-key graph");
    assert_eq!(
        decision(&product, "parents", WriteOperation::Insert),
        GraphDecision::Allow
    );
    assert_eq!(
        decision(&product, "parents", WriteOperation::Delete),
        GraphDecision::DenyReservedReachable
    );
    assert_eq!(
        decision(&product, "parents", WriteOperation::Update),
        GraphDecision::DenyReservedReachable
    );
    assert_eq!(
        decision(&product, "audit", WriteOperation::Delete),
        GraphDecision::Allow
    );
    assert_eq!(
        decision(&product, "audit", WriteOperation::Update),
        GraphDecision::DenyReservedReachable
    );
}

#[test]
fn replace_and_upsert_secondary_operations_cannot_hide_reserved_trigger_edges() {
    let rows = vec![
        table("source", "CREATE TABLE source(id INTEGER PRIMARY KEY)"),
        table("middle", "CREATE TABLE middle(id INTEGER PRIMARY KEY)"),
        table("ledger", "CREATE TABLE ledger(id INTEGER PRIMARY KEY)"),
        trigger(
            "source_insert_middle",
            "source",
            "CREATE TRIGGER source_insert_middle AFTER INSERT ON source BEGIN INSERT OR REPLACE INTO middle(id) VALUES (NEW.id); END",
        ),
        trigger(
            "middle_delete_ledger",
            "middle",
            "CREATE TRIGGER middle_delete_ledger AFTER DELETE ON middle BEGIN INSERT INTO ledger(id) VALUES (OLD.id); END",
        ),
        trigger(
            "source_update_middle",
            "source",
            "CREATE TRIGGER source_update_middle AFTER UPDATE ON source BEGIN INSERT INTO middle(id) VALUES (NEW.id) ON CONFLICT(id) DO UPDATE SET id = excluded.id; END",
        ),
        trigger(
            "middle_update_ledger",
            "middle",
            "CREATE TRIGGER middle_update_ledger AFTER UPDATE ON middle BEGIN SELECT CASE WHEN NEW.id > 0 THEN NEW.id ELSE 0 END; UPDATE ledger SET id = id; END",
        ),
    ];
    let product = derive_d1_reserved_relation_graph(&verified(rows), &["ledger".to_string()])
        .expect("secondary operation graph");
    assert_eq!(
        decision(&product, "source", WriteOperation::Insert),
        GraphDecision::DenyReservedReachable
    );
    assert_eq!(
        decision(&product, "source", WriteOperation::Update),
        GraphDecision::DenyReservedReachable
    );
}

#[test]
fn malformed_or_incomplete_catalog_graphs_fail_closed() {
    let cases = [
        (
            vec![table(
                "ledger",
                "CREATE TABLE main.ledger(id INTEGER PRIMARY KEY)",
            )],
            D1ReservedRelationGraphClassification::CatalogDefinitionUnsupported,
        ),
        (
            vec![
                table("ledger", "CREATE TABLE ledger(id INTEGER PRIMARY KEY)"),
                table(
                    "child",
                    "CREATE TABLE child(id INTEGER REFERENCES missing(id) ON DELETE CASCADE)",
                ),
            ],
            D1ReservedRelationGraphClassification::CatalogReferenceMissing,
        ),
        (
            vec![
                table("ledger", "CREATE TABLE ledger(id INTEGER PRIMARY KEY)"),
                table("items", "CREATE TABLE items(id INTEGER PRIMARY KEY)"),
                trigger(
                    "bad_target",
                    "items",
                    "CREATE TRIGGER bad_target AFTER INSERT ON items BEGIN UPDATE main.ledger SET id = id; END",
                ),
            ],
            D1ReservedRelationGraphClassification::CatalogDefinitionUnsupported,
        ),
    ];
    for (rows, expected) in cases {
        assert_eq!(
            derive_d1_reserved_relation_graph(&verified(rows), &["ledger".to_string()])
                .expect_err("malformed graph")
                .classification,
            expected
        );
    }

    assert_eq!(
        derive_d1_reserved_relation_graph(
            &verified(vec![table(
                "items",
                "CREATE TABLE items(id INTEGER PRIMARY KEY)"
            )]),
            &["ledger".to_string()]
        )
        .expect_err("reserved relation absent")
        .classification,
        D1ReservedRelationGraphClassification::ReservedRelationAbsent
    );
}

#[test]
fn configured_reserved_identifiers_are_bounded_and_case_unaliased() {
    let catalog = verified(baseline_rows());
    for reserved in [
        Vec::<String>::new(),
        vec!["sqlite_sequence".to_string()],
        vec!["d1_migrations".to_string(), "D1_MIGRATIONS".to_string()],
        vec!["bad\0name".to_string()],
    ] {
        assert!(derive_d1_reserved_relation_graph(&catalog, &reserved).is_err());
    }
}
