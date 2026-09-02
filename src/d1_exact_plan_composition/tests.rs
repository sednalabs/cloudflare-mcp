use serde_json::{Value, json};

use super::*;
use crate::d1_catalog_evidence::{
    D1_CATALOG_PROVIDER_BYTE_CAP, D1_CATALOG_PROVIDER_ROW_CAP, D1CatalogObservationFrame,
    D1CatalogProjectionRow, derive_d1_catalog_evidence_plan, prove_d1_catalog_product,
};
use crate::d1_execute_write::derive_d1_execute_write_plan;
use crate::d1_reserved_relation_graph::derive_d1_reserved_relation_graph;

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

fn table(schema_rowid: i64, name: &str) -> Value {
    let definition = format!("CREATE TABLE {name}(id INTEGER PRIMARY KEY, value TEXT)");
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
        "schema_sql_storage_class": "text",
        "table_sql_token_source_is_null": 0,
        "table_sql_token_source_hex": hex(&definition),
        "table_virtual_token_hit": 0,
        "table_replace_token_hit": 0,
        "conservative_blocker": "",
    });
    value
        .as_object_mut()
        .expect("table row")
        .extend(schema_sentinels().as_object().expect("sentinels").clone());
    value
}

fn verified(rows: Vec<Value>) -> D1CatalogEvidenceProduct {
    verified_with_observation_ids(
        rows,
        [
            "dispatch-first-0001",
            "read-first-00000001",
            "dispatch-second-001",
            "read-second-0000001",
        ],
    )
}

fn verified_with_observation_ids(
    rows: Vec<Value>,
    observation_ids: [&str; 4],
) -> D1CatalogEvidenceProduct {
    let mut rows = rows
        .into_iter()
        .map(|row| serde_json::from_value::<D1CatalogProjectionRow>(row).expect("typed row"))
        .collect::<Vec<_>>();
    rows.sort();
    let body = serde_json::to_vec(&json!({
        "version": 5,
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
    .expect("fixture payload");
    let target = target();
    let (catalog_plan, catalog_plan_sha256) =
        derive_d1_catalog_evidence_plan(&target).expect("catalog plan");
    let first = frame(
        &target,
        &catalog_plan_sha256,
        observation_ids[0],
        observation_ids[1],
        &body,
    );
    let second = frame(
        &target,
        &catalog_plan_sha256,
        observation_ids[2],
        observation_ids[3],
        &body,
    );
    prove_d1_catalog_product(
        &target,
        &catalog_plan,
        &catalog_plan_sha256,
        &first,
        &second,
    )
    .expect("verified catalog")
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

fn evidence() -> (D1CatalogEvidenceProduct, D1ReservedRelationGraphProduct) {
    evidence_with_order(false)
}

fn evidence_with_order(
    reverse: bool,
) -> (D1CatalogEvidenceProduct, D1ReservedRelationGraphProduct) {
    let mut rows = vec![
        table(1, "d1_migrations"),
        table(2, "items"),
        table(3, "other_items"),
    ];
    if reverse {
        rows.reverse();
    }
    let catalog = verified(rows);
    let graph = derive_d1_reserved_relation_graph(&catalog, &["d1_migrations".to_string()])
        .expect("reserved graph");
    (catalog, graph)
}

fn exact_plan(kind: D1WriteStatementKind, sql: &str) -> (D1ExecuteWritePlan, String) {
    let target = target();
    derive_d1_execute_write_plan(
        &target.account_id,
        &target.database_id,
        &target.target_key_sha256(),
        &"b".repeat(64),
        kind,
        sql,
        &[json!(1)],
        100,
    )
}

fn compose(
    kind: D1WriteStatementKind,
    sql: &str,
    relation: &str,
    form: D1WriteOperationForm,
    catalog: &D1CatalogEvidenceProduct,
    graph: &D1ReservedRelationGraphProduct,
) -> Result<D1ExactPlanCompositionProduct, D1ExactPlanCompositionError> {
    let (plan, plan_sha256) = exact_plan(kind, sql);
    compose_d1_exact_write_plan(
        &target(),
        &plan,
        &plan_sha256,
        relation,
        form,
        catalog,
        graph,
    )
}

fn classification(
    result: Result<D1ExactPlanCompositionProduct, D1ExactPlanCompositionError>,
) -> D1ExactPlanCompositionClassification {
    result.expect_err("fixture must deny").classification
}

fn hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

#[test]
fn every_closed_form_requires_its_complete_ordered_allow_set() {
    let (catalog, graph) = evidence();
    let cases = [
        (
            D1WriteStatementKind::Insert,
            "INSERT INTO items(value) VALUES (?)",
            D1WriteOperationForm::Insert,
            1,
        ),
        (
            D1WriteStatementKind::Update,
            "UPDATE items SET value = ?",
            D1WriteOperationForm::Update,
            1,
        ),
        (
            D1WriteStatementKind::Delete,
            "DELETE FROM items WHERE id = ?",
            D1WriteOperationForm::Delete,
            1,
        ),
        (
            D1WriteStatementKind::Replace,
            "REPLACE INTO items(id, value) VALUES (1, ?)",
            D1WriteOperationForm::Replace,
            2,
        ),
        (
            D1WriteStatementKind::Insert,
            "INSERT OR REPLACE INTO items(id, value) VALUES (1, ?)",
            D1WriteOperationForm::InsertOrReplace,
            2,
        ),
        (
            D1WriteStatementKind::Insert,
            "INSERT INTO items(id, value) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET value = excluded.value",
            D1WriteOperationForm::UpsertDoUpdate,
            2,
        ),
        (
            D1WriteStatementKind::Update,
            "UPDATE OR REPLACE items SET value = ?",
            D1WriteOperationForm::UpdateOrReplace,
            2,
        ),
    ];
    for (kind, sql, form, expected_count) in cases {
        let product = compose(kind, sql, "items", form, &catalog, &graph)
            .expect("all effective decisions allow");
        assert_eq!(product.receipt().effective_primitive_count, expected_count);
        assert_eq!(product.receipt().allow_decision_count, expected_count);
        assert_eq!(product.plan().statement_kind, kind);
        assert_eq!(product.classified_relation(), "items");
        assert_eq!(product.classified_form(), form);
        assert_eq!(product.effective_primitives().len(), expected_count);
    }
}

#[test]
fn receipt_is_deterministic_digest_bound_and_aggregate_safe() {
    let (catalog, graph) = evidence();
    let first = compose(
        D1WriteStatementKind::Insert,
        "INSERT INTO items(value) VALUES (?)",
        "items",
        D1WriteOperationForm::Insert,
        &catalog,
        &graph,
    )
    .expect("composition");
    let replay = compose(
        D1WriteStatementKind::Insert,
        "INSERT INTO items(value) VALUES (?)",
        "items",
        D1WriteOperationForm::Insert,
        &catalog,
        &graph,
    )
    .expect("exact replay");
    assert_eq!(first, replay);

    let changed_sql = compose(
        D1WriteStatementKind::Insert,
        "INSERT INTO items(value) VALUES (? + 1)",
        "items",
        D1WriteOperationForm::Insert,
        &catalog,
        &graph,
    )
    .expect("independent exact plan");
    assert_ne!(
        first.receipt().composition_sha256,
        changed_sql.receipt().composition_sha256
    );
    let changed_relation = compose(
        D1WriteStatementKind::Insert,
        "INSERT INTO items(value) VALUES (?)",
        "other_items",
        D1WriteOperationForm::Insert,
        &catalog,
        &graph,
    )
    .expect("other allowed relation");
    assert_ne!(
        first.receipt().composition_sha256,
        changed_relation.receipt().composition_sha256
    );

    let serialized = serde_json::to_string(first.receipt()).expect("receipt JSON");
    for private in [
        "acct-1",
        DATABASE_ID,
        "items",
        "INSERT",
        "value",
        "d1_migrations",
    ] {
        assert!(!serialized.contains(private));
    }
}

#[test]
fn missing_present_denied_and_unsupported_decisions_fail_closed() {
    let (catalog, graph) = evidence();
    assert_eq!(
        classification(compose(
            D1WriteStatementKind::Insert,
            "INSERT INTO absent(value) VALUES (?)",
            "absent",
            D1WriteOperationForm::Insert,
            &catalog,
            &graph,
        )),
        D1ExactPlanCompositionClassification::GraphDecisionMissing
    );
    assert_eq!(
        classification(compose(
            D1WriteStatementKind::Delete,
            "DELETE FROM d1_migrations WHERE id = ?",
            "d1_migrations",
            D1WriteOperationForm::Delete,
            &catalog,
            &graph,
        )),
        D1ExactPlanCompositionClassification::GraphDecisionDenied
    );
    assert_eq!(
        classification(compose(
            D1WriteStatementKind::Insert,
            "INSERT INTO items(value) VALUES (?)",
            "items",
            D1WriteOperationForm::UnsupportedCompound,
            &catalog,
            &graph,
        )),
        D1ExactPlanCompositionClassification::CompoundWriteUnsupported
    );
}

#[test]
fn malformed_and_contradictory_plan_target_and_relation_deny() {
    let (catalog, graph) = evidence();
    let (plan, plan_sha256) = exact_plan(
        D1WriteStatementKind::Insert,
        "INSERT INTO items(value) VALUES (?)",
    );
    assert_eq!(
        classification(compose_d1_exact_write_plan(
            &target(),
            &plan,
            &"A".repeat(64),
            "items",
            D1WriteOperationForm::Insert,
            &catalog,
            &graph,
        )),
        D1ExactPlanCompositionClassification::PlanDigestInvalid
    );

    let mut malformed_plan = plan.clone();
    malformed_plan.version = 9;
    assert_eq!(
        classification(compose_d1_exact_write_plan(
            &target(),
            &malformed_plan,
            &plan_sha256,
            "items",
            D1WriteOperationForm::Insert,
            &catalog,
            &graph,
        )),
        D1ExactPlanCompositionClassification::PlanProductMismatch
    );
    assert_eq!(
        classification(compose_d1_exact_write_plan(
            &target(),
            &plan,
            &plan_sha256,
            "Items",
            D1WriteOperationForm::Insert,
            &catalog,
            &graph,
        )),
        D1ExactPlanCompositionClassification::ClassifiedRelationInvalid
    );
    assert_eq!(
        classification(compose_d1_exact_write_plan(
            &target(),
            &plan,
            &plan_sha256,
            "items",
            D1WriteOperationForm::Update,
            &catalog,
            &graph,
        )),
        D1ExactPlanCompositionClassification::PlanFormMismatch
    );

    let other_target = normalize_d1_target("acct-2", DATABASE_ID).expect("other target");
    assert_eq!(
        classification(compose_d1_exact_write_plan(
            &other_target,
            &plan,
            &plan_sha256,
            "items",
            D1WriteOperationForm::Insert,
            &catalog,
            &graph,
        )),
        D1ExactPlanCompositionClassification::PlanTargetMismatch
    );
}

#[test]
fn malformed_products_missing_decisions_and_primitive_contradictions_deny() {
    let (catalog, graph) = evidence();
    let (plan, plan_sha256) = exact_plan(
        D1WriteStatementKind::Insert,
        "INSERT INTO items(value) VALUES (?)",
    );
    let target = target();
    let catalog_receipt = catalog.receipt().clone();
    let graph_receipt = graph.receipt().clone();

    let mut malformed_catalog = catalog_receipt.clone();
    malformed_catalog.catalog_row_count += 1;
    assert_eq!(
        classification(compose_from_verified_parts(
            &target,
            &plan,
            &plan_sha256,
            "items",
            D1WriteOperationForm::Insert,
            &malformed_catalog,
            &graph_receipt,
            &[D1RelationWriteOperation::Insert],
            |_| Some(D1ReservedRelationDecision::Allow),
        )),
        D1ExactPlanCompositionClassification::CatalogProductMismatch
    );

    let mut unsupported_catalog = catalog_receipt.clone();
    unsupported_catalog.version = 4;
    assert_eq!(
        classification(compose_from_verified_parts(
            &target,
            &plan,
            &plan_sha256,
            "items",
            D1WriteOperationForm::Insert,
            &unsupported_catalog,
            &graph_receipt,
            &[D1RelationWriteOperation::Insert],
            |_| Some(D1ReservedRelationDecision::Allow),
        )),
        D1ExactPlanCompositionClassification::CatalogProjectionUnsupported
    );

    let mut contradictory_graph = graph_receipt.clone();
    contradictory_graph.allow_count += 1;
    assert_eq!(
        classification(compose_from_verified_parts(
            &target,
            &plan,
            &plan_sha256,
            "items",
            D1WriteOperationForm::Insert,
            &catalog_receipt,
            &contradictory_graph,
            &[D1RelationWriteOperation::Insert],
            |_| Some(D1ReservedRelationDecision::Allow),
        )),
        D1ExactPlanCompositionClassification::GraphProductMismatch
    );

    let mut unsupported_graph = graph_receipt.clone();
    unsupported_graph.version = 2;
    assert_eq!(
        classification(compose_from_verified_parts(
            &target,
            &plan,
            &plan_sha256,
            "items",
            D1WriteOperationForm::Insert,
            &catalog_receipt,
            &unsupported_graph,
            &[D1RelationWriteOperation::Insert],
            |_| Some(D1ReservedRelationDecision::Allow),
        )),
        D1ExactPlanCompositionClassification::GraphProjectionUnsupported
    );

    assert_eq!(
        classification(compose_from_verified_parts(
            &target,
            &plan,
            &plan_sha256,
            "items",
            D1WriteOperationForm::Insert,
            &catalog_receipt,
            &graph_receipt,
            &[D1RelationWriteOperation::Insert],
            |_| None,
        )),
        D1ExactPlanCompositionClassification::GraphDecisionMissing
    );
    assert_eq!(
        classification(compose_from_verified_parts(
            &target,
            &plan,
            &plan_sha256,
            "items",
            D1WriteOperationForm::Insert,
            &catalog_receipt,
            &graph_receipt,
            &[D1RelationWriteOperation::Insert],
            |_| Some(D1ReservedRelationDecision::DenyTriggerEffectsUnproven),
        )),
        D1ExactPlanCompositionClassification::GraphDecisionDenied
    );
    assert_eq!(
        classification(compose_from_verified_parts(
            &target,
            &plan,
            &plan_sha256,
            "items",
            D1WriteOperationForm::Insert,
            &catalog_receipt,
            &graph_receipt,
            &[
                D1RelationWriteOperation::Insert,
                D1RelationWriteOperation::Insert,
            ],
            |_| Some(D1ReservedRelationDecision::Allow),
        )),
        D1ExactPlanCompositionClassification::PrimitiveDuplicate
    );
    assert_eq!(
        classification(compose_from_verified_parts(
            &target,
            &plan,
            &plan_sha256,
            "items",
            D1WriteOperationForm::Insert,
            &catalog_receipt,
            &graph_receipt,
            &[
                D1RelationWriteOperation::Insert,
                D1RelationWriteOperation::Delete,
            ],
            |_| Some(D1ReservedRelationDecision::Allow),
        )),
        D1ExactPlanCompositionClassification::PrimitiveExpansionMismatch
    );

    assert_eq!(
        classification(compose_from_verified_parts(
            &target,
            &plan,
            &plan_sha256,
            "items",
            D1WriteOperationForm::UpsertDoUpdate,
            &catalog_receipt,
            &graph_receipt,
            &[
                D1RelationWriteOperation::Update,
                D1RelationWriteOperation::Insert,
            ],
            |_| Some(D1ReservedRelationDecision::Allow),
        )),
        D1ExactPlanCompositionClassification::PrimitiveExpansionMismatch
    );
}

#[test]
fn evidence_arrival_order_does_not_change_exact_composition() {
    let (first_catalog, first_graph) = evidence_with_order(false);
    let (second_catalog, second_graph) = evidence_with_order(true);
    let first = compose(
        D1WriteStatementKind::Insert,
        "INSERT INTO items(value) VALUES (?)",
        "items",
        D1WriteOperationForm::Insert,
        &first_catalog,
        &first_graph,
    )
    .expect("first ordering");
    let second = compose(
        D1WriteStatementKind::Insert,
        "INSERT INTO items(value) VALUES (?)",
        "items",
        D1WriteOperationForm::Insert,
        &second_catalog,
        &second_graph,
    )
    .expect("second ordering");
    assert_eq!(first.receipt(), second.receipt());
}

#[test]
fn fresh_observation_identities_preserve_exact_semantic_composition() {
    let rows = vec![
        table(1, "d1_migrations"),
        table(2, "items"),
        table(3, "other_items"),
    ];
    let first_catalog = verified_with_observation_ids(
        rows.clone(),
        [
            "dispatch-dry-first",
            "read-dry-first-0001",
            "dispatch-dry-second",
            "read-dry-second-001",
        ],
    );
    let second_catalog = verified_with_observation_ids(
        rows,
        [
            "dispatch-live-first",
            "read-live-first-001",
            "dispatch-live-second",
            "read-live-second-01",
        ],
    );
    assert_ne!(
        first_catalog.receipt().observation_pair_sha256,
        second_catalog.receipt().observation_pair_sha256,
        "fresh physical observations must retain distinct custody identities"
    );
    let first_graph =
        derive_d1_reserved_relation_graph(&first_catalog, &["d1_migrations".to_string()])
            .expect("first reserved graph");
    let second_graph =
        derive_d1_reserved_relation_graph(&second_catalog, &["d1_migrations".to_string()])
            .expect("second reserved graph");
    let first = compose(
        D1WriteStatementKind::Update,
        "UPDATE items SET value = ?",
        "items",
        D1WriteOperationForm::Update,
        &first_catalog,
        &first_graph,
    )
    .expect("dry-run composition");
    let second = compose(
        D1WriteStatementKind::Update,
        "UPDATE items SET value = ?",
        "items",
        D1WriteOperationForm::Update,
        &second_catalog,
        &second_graph,
    )
    .expect("live composition");
    assert_eq!(
        first.receipt(),
        second.receipt(),
        "fresh observation custody must not make an unchanged semantic approval unreplayable"
    );
}
