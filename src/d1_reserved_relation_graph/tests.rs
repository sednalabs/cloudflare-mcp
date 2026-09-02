use serde_json::{Value, json};

use super::*;
use crate::d1_catalog_evidence::{
    D1_CATALOG_PROVIDER_BYTE_CAP, D1_CATALOG_PROVIDER_ROW_CAP, D1CatalogObservationFrame,
    D1CatalogProjectionRow, derive_d1_catalog_evidence_plan, prove_d1_catalog_product,
};
use crate::d1_target::{D1TargetIdentity, normalize_d1_target};

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

fn table(schema_rowid: i64, name: &str, definition: Option<&str>) -> Value {
    let oversized = definition.is_some_and(|source| source.len() > 64 * 1024);
    let virtual_token_hit = definition.is_some_and(|source| {
        source
            .as_bytes()
            .windows(b"VIRTUAL".len())
            .any(|window| window.eq_ignore_ascii_case(b"VIRTUAL"))
    });
    let replace_token_hit = definition.is_some_and(|source| {
        source
            .as_bytes()
            .windows(b"REPLACE".len())
            .any(|window| window.eq_ignore_ascii_case(b"REPLACE"))
    });
    let blocker = if definition.is_none() {
        "table_sql_token_source_unavailable"
    } else if oversized {
        "table_sql_token_source_oversized"
    } else if virtual_token_hit {
        "table_virtual_semantics_unproven"
    } else if replace_token_hit {
        "table_replace_semantics_unproven"
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
        "table_replace_token_hit": u8::from(replace_token_hit && !oversized),
        "conservative_blocker": blocker,
    });
    value
        .as_object_mut()
        .expect("table row")
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
        "table_replace_token_hit": 0,
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
        "table_replace_token_hit": 0,
        "conservative_blocker": if owner_resolved { "trigger_effects_unproven" } else { "schema_owner_unresolved" },
    });
    value
        .as_object_mut()
        .expect("trigger row")
        .extend(schema_sentinels().as_object().expect("sentinels").clone());
    value
}

fn auxiliary(schema_rowid: i64, name: &str, owner: &str) -> Value {
    let mut value = json!({
        "schema_rowid": schema_rowid,
        "fact_order": 0,
        "fact_kind": "schema_auxiliary",
        "relation_type_storage_class": "text",
        "relation_type_value_hex": hex("index"),
        "relation_type": "index",
        "relation_name_storage_class": "text",
        "relation_name_hex": hex(name),
        "owner_name_storage_class": "text",
        "owner_name_hex": hex(owner),
        "schema_sql_storage_class": "text",
        "table_sql_token_source_is_null": 1,
        "table_sql_token_source_hex": "",
        "table_virtual_token_hit": 0,
        "table_replace_token_hit": 0,
        "conservative_blocker": "",
    });
    value
        .as_object_mut()
        .expect("index row")
        .extend(schema_sentinels().as_object().expect("sentinels").clone());
    value
}

#[allow(clippy::too_many_arguments)]
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
        "table_replace_token_hit": 0,
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

fn verified(rows: Vec<Value>) -> D1CatalogEvidenceProduct {
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
        .expect("verified catalog product")
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

fn baseline() -> Vec<Value> {
    vec![
        table(
            1,
            "d1_migrations",
            Some("CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY, name TEXT)"),
        ),
        table(
            2,
            "items",
            Some("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT)"),
        ),
    ]
}

fn roots() -> Vec<String> {
    vec!["d1_migrations".to_string()]
}

fn hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

#[test]
fn verified_facts_produce_one_deterministic_aggregate_only_product() {
    let mut rows = baseline();
    rows.push(auxiliary(3, "items_by_value", "items"));
    let catalog = verified(rows);
    let first = derive_d1_reserved_relation_graph(&catalog, &roots()).expect("graph");
    let second = derive_d1_reserved_relation_graph(&catalog, &roots()).expect("stable graph");
    assert_eq!(first, second);
    assert_eq!(first.receipt().relation_count, 2);
    assert_eq!(first.receipt().schema_auxiliary_fact_count, 1);
    assert_eq!(first.receipt().graph_node_count, 6);
    assert_eq!(first.receipt().graph_edge_count, 0);
    assert_eq!(first.receipt().allow_count, 3);
    assert_eq!(first.receipt().deny_reserved_reachable_count, 3);
    assert_eq!(
        first.decision_for("ITEMS", D1RelationWriteOperation::Insert),
        Some(D1ReservedRelationDecision::Allow)
    );
    assert_eq!(
        first.decision_for("d1_migrations", D1RelationWriteOperation::Delete),
        Some(D1ReservedRelationDecision::DenyReservedReachable)
    );
    let encoded = serde_json::to_string(first.receipt()).expect("receipt");
    for private in ["d1_migrations", "items", "items_by_value", DATABASE_ID] {
        assert!(!encoded.contains(private));
    }
}

#[test]
fn views_and_trigger_owned_relations_are_explicit_denials_without_parsing_sql() {
    let mut rows = baseline();
    rows.extend([
        view(3, "item_view"),
        trigger(4, "items_after_insert", "items", true),
        trigger(5, "items_before_delete", "items", true),
        auxiliary(6, "items_by_value", "items"),
    ]);
    let product = derive_d1_reserved_relation_graph(&verified(rows), &roots()).expect("graph");
    for operation in D1RelationWriteOperation::ALL {
        assert_eq!(
            product.decision_for("items", operation),
            Some(D1ReservedRelationDecision::DenyTriggerEffectsUnproven)
        );
        assert_eq!(
            product.decision_for("item_view", operation),
            Some(D1ReservedRelationDecision::DenyViewWriteSemanticsUnproven)
        );
    }
    assert_eq!(product.receipt().trigger_fact_count, 2);
    assert_eq!(product.receipt().trigger_owned_relation_count, 1);
    assert_eq!(product.receipt().schema_auxiliary_fact_count, 1);
    assert_eq!(product.receipt().graph_node_count, 9);
}

#[test]
fn reserved_reachability_has_stable_precedence_over_view_and_trigger_uncertainty() {
    let rows = vec![
        table(1, "ledger", Some("CREATE TABLE ledger(id)")),
        trigger(2, "ledger_trigger", "ledger", true),
        view(3, "reserved_view"),
    ];
    let product = derive_d1_reserved_relation_graph(
        &verified(rows),
        &["ledger".to_string(), "reserved_view".to_string()],
    )
    .expect("closed roots");
    for operation in D1RelationWriteOperation::ALL {
        assert_eq!(
            product.decision_for("ledger", operation),
            Some(D1ReservedRelationDecision::DenyReservedReachable)
        );
        assert_eq!(
            product.decision_for("reserved_view", operation),
            Some(D1ReservedRelationDecision::DenyReservedReachable)
        );
    }
    assert_eq!(product.receipt().deny_reserved_reachable_count, 6);
    assert_eq!(product.receipt().deny_trigger_effects_unproven_count, 0);
    assert_eq!(
        product.receipt().deny_view_write_semantics_unproven_count,
        0
    );
}

#[test]
fn composite_foreign_key_actions_are_operation_specific_and_reach_reserved_roots() {
    let rows = vec![
        table(
            1,
            "reserved_child",
            Some("CREATE TABLE reserved_child(left_id, right_id)"),
        ),
        foreign_key(
            1,
            "reserved_child",
            "parents",
            0,
            0,
            "left_id",
            Some("left_id"),
            "SET NULL",
            "CASCADE",
            "FULL",
            true,
        ),
        foreign_key(
            1,
            "reserved_child",
            "parents",
            0,
            1,
            "right_id",
            None,
            "SET NULL",
            "CASCADE",
            "FULL",
            true,
        ),
        table(
            2,
            "parents",
            Some("CREATE TABLE parents(left_id, right_id)"),
        ),
        table(3, "safe_child", Some("CREATE TABLE safe_child(parent_id)")),
        foreign_key(
            3,
            "safe_child",
            "parents",
            0,
            0,
            "parent_id",
            Some("left_id"),
            "NO ACTION",
            "RESTRICT",
            "NONE",
            true,
        ),
    ];
    let product =
        derive_d1_reserved_relation_graph(&verified(rows), &["reserved_child".to_string()])
            .expect("foreign-key graph");
    assert_eq!(
        product.decision_for("parents", D1RelationWriteOperation::Insert),
        Some(D1ReservedRelationDecision::Allow)
    );
    assert_eq!(
        product.decision_for("parents", D1RelationWriteOperation::Update),
        Some(D1ReservedRelationDecision::DenyReservedReachable)
    );
    assert_eq!(
        product.decision_for("parents", D1RelationWriteOperation::Delete),
        Some(D1ReservedRelationDecision::DenyReservedReachable)
    );
    assert_eq!(product.receipt().foreign_key_fact_count, 3);
    assert_eq!(product.receipt().foreign_key_group_count, 2);
    assert_eq!(product.receipt().graph_edge_count, 2);
}

#[test]
fn foreign_key_cycles_terminate_and_propagate_trigger_blockers() {
    let rows = vec![
        table(1, "ledger", Some("CREATE TABLE ledger(id)")),
        table(2, "left_side", Some("CREATE TABLE left_side(id)")),
        foreign_key(
            2,
            "left_side",
            "right_side",
            0,
            0,
            "id",
            Some("id"),
            "CASCADE",
            "CASCADE",
            "NONE",
            true,
        ),
        table(3, "right_side", Some("CREATE TABLE right_side(id)")),
        foreign_key(
            3,
            "right_side",
            "left_side",
            0,
            0,
            "id",
            Some("id"),
            "CASCADE",
            "CASCADE",
            "NONE",
            true,
        ),
        trigger(4, "right_trigger", "right_side", true),
    ];
    let product = derive_d1_reserved_relation_graph(&verified(rows), &["ledger".to_string()])
        .expect("cycle-safe graph");
    assert_eq!(product.receipt().graph_edge_count, 4);
    for operation in [
        D1RelationWriteOperation::Update,
        D1RelationWriteOperation::Delete,
    ] {
        assert_eq!(
            product.decision_for("left_side", operation),
            Some(D1ReservedRelationDecision::DenyTriggerEffectsUnproven)
        );
        assert_eq!(
            product.decision_for("right_side", operation),
            Some(D1ReservedRelationDecision::DenyTriggerEffectsUnproven)
        );
    }
    assert_eq!(
        product.decision_for("left_side", D1RelationWriteOperation::Insert),
        Some(D1ReservedRelationDecision::Allow)
    );
}

#[test]
fn bounded_autoincrement_token_creates_only_the_implicit_sequence_edge() {
    let rows = vec![
        table(1, "ledger", Some("CREATE TABLE ledger(id)")),
        table(
            2,
            "items",
            Some("CREATE TABLE items(id INTEGER PRIMARY KEY AUTOINCREMENT)"),
        ),
        table(
            3,
            "sqlite_sequence",
            Some("CREATE TABLE sqlite_sequence(name,seq)"),
        ),
    ];
    let product = derive_d1_reserved_relation_graph(&verified(rows), &["ledger".to_string()])
        .expect("autoincrement graph");
    assert_eq!(product.receipt().autoincrement_relation_count, 1);
    assert_eq!(product.receipt().automatic_reserved_root_count, 1);
    assert_eq!(product.receipt().graph_edge_count, 1);
    assert_eq!(
        product.decision_for("items", D1RelationWriteOperation::Insert),
        Some(D1ReservedRelationDecision::DenyReservedReachable)
    );
    assert_eq!(
        product.decision_for("items", D1RelationWriteOperation::Update),
        Some(D1ReservedRelationDecision::Allow)
    );

    let missing_sequence = verified(vec![
        table(1, "ledger", Some("CREATE TABLE ledger(id)")),
        table(
            2,
            "items",
            Some("CREATE TABLE items(id INTEGER PRIMARY KEY AUTOINCREMENT)"),
        ),
    ]);
    assert_eq!(
        derive_d1_reserved_relation_graph(&missing_sequence, &["ledger".to_string()])
            .expect_err("implicit target is required")
            .classification,
        D1ReservedRelationGraphClassification::AutoincrementEvidenceUnsupported
    );
}

#[test]
fn every_projection_blocker_family_denies_the_complete_graph() {
    let missing_sql = verified(vec![
        table(1, "ledger", Some("CREATE TABLE ledger(id)")),
        table(2, "opaque", None),
    ]);
    assert_eq!(
        derive_d1_reserved_relation_graph(&missing_sql, &["ledger".to_string()])
            .expect_err("missing token source blocks")
            .classification,
        D1ReservedRelationGraphClassification::CatalogFactBlocked
    );

    let unresolved_fk = verified(vec![
        table(1, "ledger", Some("CREATE TABLE ledger(id)")),
        table(2, "child", Some("CREATE TABLE child(parent_id)")),
        foreign_key(
            2,
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
    ]);
    assert_eq!(
        derive_d1_reserved_relation_graph(&unresolved_fk, &["ledger".to_string()])
            .expect_err("unresolved foreign key blocks")
            .classification,
        D1ReservedRelationGraphClassification::CatalogFactBlocked
    );

    let mut malformed_fk = foreign_key(
        2,
        "child",
        "ledger",
        0,
        0,
        "parent_id",
        Some("id"),
        "NO ACTION",
        "CASCADE",
        "NONE",
        true,
    );
    malformed_fk["fact_kind"] = json!("foreign_key_blocker");
    malformed_fk["parent_name_storage_class"] = json!("blob");
    malformed_fk["conservative_blocker"] = json!("foreign_key_parent_storage_class_invalid");
    let explicit_fk_blocker = verified(vec![
        table(1, "ledger", Some("CREATE TABLE ledger(id)")),
        table(2, "child", Some("CREATE TABLE child(parent_id)")),
        malformed_fk,
    ]);
    assert_eq!(
        derive_d1_reserved_relation_graph(&explicit_fk_blocker, &["ledger".to_string()])
            .expect_err("foreign-key blocker denies")
            .classification,
        D1ReservedRelationGraphClassification::CatalogFactBlocked
    );

    let malformed_schema = verified(vec![
        table(1, "ledger", Some("CREATE TABLE ledger(id)")),
        trigger(2, "orphan", "missing", false),
    ]);
    assert_eq!(
        derive_d1_reserved_relation_graph(&malformed_schema, &["ledger".to_string()])
            .expect_err("schema blocker denies")
            .classification,
        D1ReservedRelationGraphClassification::CatalogFactBlocked
    );
}

#[test]
fn virtual_table_evidence_blocks_graph_before_shadow_root_allowance() {
    let catalog = verified(vec![
        table(1, "ledger", Some("CREATE TABLE ledger(id)")),
        table(
            2,
            "documents",
            Some("CrEaTe ViRtUaL TABLE documents USING fts5(body)"),
        ),
        table(
            3,
            "documents_data",
            Some("CREATE TABLE documents_data(id INTEGER PRIMARY KEY, block BLOB)"),
        ),
    ]);
    assert_eq!(catalog.receipt().conservative_blocker_count, 1);
    assert_eq!(catalog.rows()[1].table_virtual_token_hit, 1);
    assert_eq!(
        derive_d1_reserved_relation_graph(&catalog, &["documents_data".to_string()])
            .expect_err("virtual module can write configured shadow roots")
            .classification,
        D1ReservedRelationGraphClassification::CatalogFactBlocked
    );

    let mut malformed_rows = catalog.rows().to_vec();
    malformed_rows[1].table_virtual_token_hit = 2;
    assert_eq!(
        derive_from_verified_parts(
            catalog.receipt(),
            &malformed_rows,
            &["documents_data".to_string()]
        )
        .expect_err("non-boolean virtual evidence denies defensively")
        .classification,
        D1ReservedRelationGraphClassification::CatalogFactBlocked
    );
}

#[test]
fn schema_replace_blocks_plain_insert_and_update_before_reserved_delete_cascade() {
    let catalog = verified(vec![
        table(
            1,
            "reserved_child",
            Some("CREATE TABLE reserved_child(parent_id)"),
        ),
        foreign_key(
            1,
            "reserved_child",
            "parents",
            0,
            0,
            "parent_id",
            Some("id"),
            "NO ACTION",
            "CASCADE",
            "NONE",
            true,
        ),
        table(
            2,
            "parents",
            Some("CREATE TABLE parents(id, UNIQUE(id) ON CONFLICT REPLACE)"),
        ),
    ]);
    let replace_relation = catalog
        .rows()
        .iter()
        .find(|row| row.relation_name_hex == hex("parents"))
        .expect("REPLACE relation");
    assert_eq!(replace_relation.table_replace_token_hit, 1);
    assert_eq!(catalog.receipt().conservative_blocker_count, 1);

    assert_eq!(
        required_relation_write_operations(D1WriteOperationForm::Insert)
            .expect("plain INSERT form"),
        &[D1RelationWriteOperation::Insert]
    );
    assert_eq!(
        required_relation_write_operations(D1WriteOperationForm::Update)
            .expect("plain UPDATE form"),
        &[D1RelationWriteOperation::Update]
    );
    assert_eq!(
        derive_d1_reserved_relation_graph(&catalog, &["reserved_child".to_string()])
            .expect_err("schema REPLACE can delete an incumbent and cascade")
            .classification,
        D1ReservedRelationGraphClassification::CatalogFactBlocked
    );

    let encoded = serde_json::to_string(catalog.receipt()).expect("aggregate catalog receipt");
    for private in [
        "REPLACE",
        "parents",
        "reserved_child",
        "UNIQUE(id)",
        DATABASE_ID,
    ] {
        assert!(!encoded.contains(private));
    }
}

#[test]
fn compound_write_forms_expand_to_every_required_primitive() {
    use D1RelationWriteOperation::{Delete, Insert, Update};
    use D1WriteOperationForm::{
        Delete as DeleteForm, Insert as InsertForm, InsertOrReplace, Replace, UnsupportedCompound,
        Update as UpdateForm, UpdateOrReplace, UpsertDoUpdate,
    };

    for (form, expected) in [
        (InsertForm, &[Insert][..]),
        (UpdateForm, &[Update][..]),
        (DeleteForm, &[Delete][..]),
        (Replace, &[Delete, Insert][..]),
        (InsertOrReplace, &[Delete, Insert][..]),
        (UpsertDoUpdate, &[Insert, Update][..]),
        (UpdateOrReplace, &[Update, Delete][..]),
    ] {
        assert_eq!(
            required_relation_write_operations(form).expect("supported expansion"),
            expected
        );
    }
    assert_eq!(
        required_relation_write_operations(UnsupportedCompound)
            .expect_err("unknown compound form denies")
            .classification,
        D1ReservedRelationGraphClassification::CompoundWriteUnsupported
    );

    let product = derive_d1_reserved_relation_graph(
        &verified(vec![
            table(
                1,
                "reserved_child",
                Some("CREATE TABLE reserved_child(parent_id)"),
            ),
            foreign_key(
                1,
                "reserved_child",
                "parents",
                0,
                0,
                "parent_id",
                Some("id"),
                "SET NULL",
                "CASCADE",
                "NONE",
                true,
            ),
            table(2, "parents", Some("CREATE TABLE parents(id)")),
        ]),
        &["reserved_child".to_string()],
    )
    .expect("operation-specific graph");
    for form in [Replace, InsertOrReplace, UpsertDoUpdate] {
        let decisions = required_relation_write_operations(form)
            .expect("supported form")
            .iter()
            .map(|operation| {
                product
                    .decision_for("parents", *operation)
                    .expect("decision")
            })
            .collect::<Vec<_>>();
        assert!(decisions.contains(&D1ReservedRelationDecision::Allow));
        assert!(decisions.contains(&D1ReservedRelationDecision::DenyReservedReachable));
        assert!(
            !decisions
                .iter()
                .all(|decision| *decision == D1ReservedRelationDecision::Allow)
        );
    }

    let delete_only = derive_d1_reserved_relation_graph(
        &verified(vec![
            table(
                1,
                "reserved_child",
                Some("CREATE TABLE reserved_child(parent_id)"),
            ),
            foreign_key(
                1,
                "reserved_child",
                "parents",
                0,
                0,
                "parent_id",
                Some("id"),
                "NO ACTION",
                "CASCADE",
                "NONE",
                true,
            ),
            table(2, "parents", Some("CREATE TABLE parents(id)")),
        ]),
        &["reserved_child".to_string()],
    )
    .expect("delete-only graph");
    let update_or_replace = required_relation_write_operations(UpdateOrReplace)
        .expect("supported form")
        .iter()
        .map(|operation| {
            delete_only
                .decision_for("parents", *operation)
                .expect("decision")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        update_or_replace,
        vec![
            D1ReservedRelationDecision::Allow,
            D1ReservedRelationDecision::DenyReservedReachable,
        ]
    );
}

#[test]
fn defensive_product_and_future_fact_drift_fail_closed() {
    let catalog = verified(baseline());
    let mut mismatched_receipt = catalog.receipt().clone();
    mismatched_receipt.catalog_row_count += 1;
    assert_eq!(
        derive_from_verified_parts(&mismatched_receipt, catalog.rows(), &roots())
            .expect_err("receipt drift")
            .classification,
        D1ReservedRelationGraphClassification::CatalogProductMismatch
    );

    let mut future_rows = catalog.rows().to_vec();
    future_rows[0].fact_kind = "future_relation_fact".to_string();
    let mut future_receipt = catalog.receipt().clone();
    future_receipt.relation_fact_count -= 1;
    assert_eq!(
        derive_from_verified_parts(&future_receipt, &future_rows, &roots())
            .expect_err("future fact must not default allow")
            .classification,
        D1ReservedRelationGraphClassification::CatalogFactUnsupported
    );

    let mut malformed_rows = catalog.rows().to_vec();
    malformed_rows[0].relation_name_hex = "6c6564676572".to_string();
    assert_eq!(
        derive_from_verified_parts(catalog.receipt(), &malformed_rows, &roots())
            .expect_err("noncanonical hex must deny")
            .classification,
        D1ReservedRelationGraphClassification::CatalogTextInvalid
    );
}

#[test]
fn reserved_roots_are_closed_bounded_present_and_case_collision_free() {
    let catalog = verified(baseline());
    let cases = [
        (
            Vec::<String>::new(),
            D1ReservedRelationGraphClassification::ReservedRootInvalid,
        ),
        (
            vec!["sqlite_sequence".to_string()],
            D1ReservedRelationGraphClassification::ReservedRootInvalid,
        ),
        (
            vec!["d1_migrations".to_string(), "D1_MIGRATIONS".to_string()],
            D1ReservedRelationGraphClassification::ReservedRootDuplicate,
        ),
        (
            vec!["missing".to_string()],
            D1ReservedRelationGraphClassification::ReservedRootAbsent,
        ),
    ];
    for (roots, expected) in cases {
        assert_eq!(
            derive_d1_reserved_relation_graph(&catalog, &roots)
                .expect_err("invalid reserved roots")
                .classification,
            expected
        );
    }
    let excessive = (0..=MAX_CONFIGURED_RESERVED_ROOTS)
        .map(|index| format!("root_{index}"))
        .collect::<Vec<_>>();
    assert_eq!(
        derive_d1_reserved_relation_graph(&catalog, &excessive)
            .expect_err("configured roots are bounded")
            .classification,
        D1ReservedRelationGraphClassification::ReservedRootInvalid
    );
}
