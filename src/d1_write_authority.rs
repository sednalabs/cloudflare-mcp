//! Side-effect-free catalog authority for one generic D1 DML statement.
//!
//! This is a pre-provider boundary only. It derives one fixed bounded catalog
//! query and admits a DML statement only after two independently primary-served
//! readbacks prove the same complete table/view/trigger graph. The graph is
//! parsed locally so direct, quoted, view-mediated, trigger-mediated, and
//! SQLite-implicit writes cannot reach SQLite, Cloudflare, or configured
//! migration-ledger relations.
//! Provider dispatch, mutation custody, recovery, and public tool routing are
//! deliberately owned by later boundaries.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::d1_execute_write::D1WriteStatementKind;
use crate::d1_migration_manifest::is_supported_d1_migration_ledger_table_sql;
use crate::d1_target::{D1TargetIdentity, normalize_d1_target};

pub(crate) const D1_WRITE_CATALOG_AUTHORITY_OPERATION: &str = "d1_write_catalog_authority";
pub(crate) const D1_WRITE_CATALOG_MAX_OBJECTS: usize = 1_000;
pub(crate) const D1_WRITE_CATALOG_REQUIRED_PROVIDER_ROW_CAP: usize =
    D1_WRITE_CATALOG_MAX_OBJECTS + 1;
const D1_WRITE_SQL_MAX_BYTES: usize = 1024 * 1024;
const D1_WRITE_CATALOG_SQL_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1WriteCatalogAuthorityPlan {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) account_id: String,
    pub(crate) database_id: String,
    pub(crate) target_key_sha256: String,
    pub(crate) statement_kind: D1WriteStatementKind,
    pub(crate) sql_sha256: String,
    pub(crate) sql_size_bytes: usize,
    pub(crate) target_relation_sha256: String,
    pub(crate) reserved_relation_set_sha256: String,
    pub(crate) reserved_relation_count: usize,
    pub(crate) catalog_query_sha256: String,
    pub(crate) catalog_query_size_bytes: usize,
    pub(crate) max_catalog_objects: usize,
    pub(crate) required_provider_row_cap: usize,
    #[serde(skip)]
    target_relation: String,
    #[serde(skip)]
    trigger_events: Vec<TriggerEvent>,
    #[serde(skip)]
    configured_ledgers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1WriteCatalogAuthorityReceipt {
    pub(crate) version: u8,
    pub(crate) operation: &'static str,
    pub(crate) target_key_sha256: String,
    pub(crate) statement_kind: D1WriteStatementKind,
    pub(crate) target_relation_sha256: String,
    pub(crate) reserved_relation_set_sha256: String,
    pub(crate) catalog_query_sha256: String,
    pub(crate) catalog_snapshot_sha256: String,
    pub(crate) catalog_object_count: usize,
    pub(crate) catalog_trigger_count: usize,
    pub(crate) reachable_relation_count: usize,
    pub(crate) stable_primary_readbacks: u8,
    pub(crate) provider_row_cap: usize,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1WriteAuthorityClassification {
    TargetIdentityInvalid,
    SqlEmptyOrOversized,
    SqlMalformedOrUnsupported,
    SqlMultipleStatements,
    SqlSchemaQualifiedTarget,
    ConfiguredLedgerInvalid,
    ConfiguredLedgerDuplicate,
    ReservedRelationTarget,
    CatalogResponseMalformed,
    CatalogReadNotPrimary,
    CatalogReadReportedMutation,
    CatalogReadTruncated,
    CatalogReadCapInsufficient,
    CatalogObjectLimitExceeded,
    CatalogRowNonText,
    CatalogRowDuplicate,
    CatalogSchemaMalformed,
    CatalogReadbacksUnstable,
    ConfiguredLedgerAbsent,
    ConfiguredLedgerSchemaDrift,
    TargetRelationAbsent,
    ViewMutationUnproven,
    ReservedRelationReachable,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1WriteAuthorityError {
    pub(crate) code: &'static str,
    pub(crate) classification: D1WriteAuthorityClassification,
    pub(crate) message: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TriggerEvent {
    Insert,
    Update,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TriggerTiming {
    Before,
    After,
    InsteadOf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForeignKeyAction {
    NoAction,
    Restrict,
    SetNull,
    SetDefault,
    Cascade,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SqlToken {
    Word(String),
    Identifier(String),
    StringLiteral,
    Symbol(char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedDml {
    statement_kind: D1WriteStatementKind,
    target_relation: String,
    trigger_events: Vec<TriggerEvent>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct CatalogRow {
    object_type: String,
    name: String,
    parent_name: String,
    sql: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelationKind {
    Table,
    View,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Relation {
    kind: RelationKind,
    exact_name: String,
    sql: String,
    autoincrement: bool,
    foreign_keys: Vec<ForeignKeyDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForeignKeyDefinition {
    parent_relation: String,
    on_delete: ForeignKeyAction,
    on_update: ForeignKeyAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Trigger {
    timing: TriggerTiming,
    event: TriggerEvent,
    effects: Vec<ParsedDml>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CatalogSnapshot {
    rows: Vec<CatalogRow>,
    relations: BTreeMap<String, Relation>,
    triggers_by_parent: BTreeMap<String, Vec<Trigger>>,
    implicit_writes_by_parent: BTreeMap<(String, TriggerEvent), Vec<(String, TriggerEvent)>>,
}

pub(crate) fn derive_d1_write_catalog_authority_plan(
    target: &D1TargetIdentity,
    sql: &str,
    configured_migrations_tables: &[String],
) -> Result<(D1WriteCatalogAuthorityPlan, String, String), D1WriteAuthorityError> {
    if !matches!(
        normalize_d1_target(&target.account_id, &target.database_id),
        Ok(canonical) if canonical == *target
    ) {
        return Err(authority_error(
            D1WriteAuthorityClassification::TargetIdentityInvalid,
            "D1 write authority did not receive one canonical target identity",
        ));
    }
    if sql.is_empty() || sql.len() > D1_WRITE_SQL_MAX_BYTES {
        return Err(authority_error(
            D1WriteAuthorityClassification::SqlEmptyOrOversized,
            "D1 DML SQL was empty or exceeded the bounded authority input",
        ));
    }
    let parsed = parse_one_dml(sql)?;
    let configured_ledgers = normalize_configured_ledgers(configured_migrations_tables)?;
    if is_reserved_relation(&parsed.target_relation, &configured_ledgers) {
        return Err(authority_error(
            D1WriteAuthorityClassification::ReservedRelationTarget,
            "D1 DML directly targeted a reserved relation",
        ));
    }
    let catalog_query = format!(
        "SELECT type, name, tbl_name, sql FROM sqlite_master \
         WHERE type IN ('table', 'view', 'trigger') \
         ORDER BY type COLLATE BINARY, name COLLATE BINARY \
         LIMIT {}",
        D1_WRITE_CATALOG_REQUIRED_PROVIDER_ROW_CAP
    );
    let reserved_relation_set_sha256 = hash_serialized(
        &configured_ledgers
            .iter()
            .map(|(identity, exact)| (identity.as_str(), exact.as_str()))
            .collect::<Vec<_>>(),
    );
    let plan = D1WriteCatalogAuthorityPlan {
        version: 2,
        operation: D1_WRITE_CATALOG_AUTHORITY_OPERATION,
        account_id: target.account_id.clone(),
        database_id: target.database_id.clone(),
        target_key_sha256: target.target_key_sha256(),
        statement_kind: parsed.statement_kind,
        sql_sha256: sha256_hex(sql.as_bytes()),
        sql_size_bytes: sql.len(),
        target_relation_sha256: sha256_hex(parsed.target_relation.as_bytes()),
        reserved_relation_set_sha256,
        reserved_relation_count: configured_ledgers.len(),
        catalog_query_sha256: sha256_hex(catalog_query.as_bytes()),
        catalog_query_size_bytes: catalog_query.len(),
        max_catalog_objects: D1_WRITE_CATALOG_MAX_OBJECTS,
        required_provider_row_cap: D1_WRITE_CATALOG_REQUIRED_PROVIDER_ROW_CAP,
        target_relation: parsed.target_relation,
        trigger_events: parsed.trigger_events,
        configured_ledgers,
    };
    let plan_sha256 = hash_serialized(&plan);
    Ok((plan, plan_sha256, catalog_query))
}

pub(crate) fn authorize_d1_write_catalog(
    plan: &D1WriteCatalogAuthorityPlan,
    first_readback: &Value,
    second_readback: &Value,
) -> Result<D1WriteCatalogAuthorityReceipt, D1WriteAuthorityError> {
    let first = parse_catalog_readback(plan, first_readback)?;
    let second = parse_catalog_readback(plan, second_readback)?;
    if first.rows != second.rows {
        return Err(authority_error(
            D1WriteAuthorityClassification::CatalogReadbacksUnstable,
            "two primary catalog readbacks did not prove one stable schema graph",
        ));
    }
    validate_configured_ledgers(&first, &plan.configured_ledgers)?;
    let reachable_relation_count = prove_reachability(plan, &first)?;
    let catalog_snapshot_sha256 = hash_serialized(&first.rows);
    Ok(D1WriteCatalogAuthorityReceipt {
        version: 2,
        operation: D1_WRITE_CATALOG_AUTHORITY_OPERATION,
        target_key_sha256: plan.target_key_sha256.clone(),
        statement_kind: plan.statement_kind,
        target_relation_sha256: plan.target_relation_sha256.clone(),
        reserved_relation_set_sha256: plan.reserved_relation_set_sha256.clone(),
        catalog_query_sha256: plan.catalog_query_sha256.clone(),
        catalog_snapshot_sha256,
        catalog_object_count: first.rows.len(),
        catalog_trigger_count: first.triggers_by_parent.values().map(Vec::len).sum(),
        reachable_relation_count,
        stable_primary_readbacks: 2,
        provider_row_cap: plan.required_provider_row_cap,
    })
}

fn normalize_configured_ledgers(
    values: &[String],
) -> Result<BTreeMap<String, String>, D1WriteAuthorityError> {
    if values.is_empty() {
        return Err(authority_error(
            D1WriteAuthorityClassification::ConfiguredLedgerInvalid,
            "at least one exact configured migration-ledger identity is required",
        ));
    }
    let mut normalized = BTreeMap::new();
    for value in values {
        let mut bytes = value.bytes();
        let valid = value.len() <= 64
            && matches!(bytes.next(), Some(byte) if byte == b'_' || byte.is_ascii_alphabetic())
            && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
            && value == value.trim();
        if !valid || is_reserved_family(value) {
            return Err(authority_error(
                D1WriteAuthorityClassification::ConfiguredLedgerInvalid,
                "a configured migration-ledger identity was not canonical bounded ASCII",
            ));
        }
        let identity = ascii_identity(value);
        if normalized.insert(identity, value.clone()).is_some() {
            return Err(authority_error(
                D1WriteAuthorityClassification::ConfiguredLedgerDuplicate,
                "configured migration-ledger identities collided under SQLite ASCII identity",
            ));
        }
    }
    Ok(normalized)
}

fn parse_catalog_readback(
    plan: &D1WriteCatalogAuthorityPlan,
    value: &Value,
) -> Result<CatalogSnapshot, D1WriteAuthorityError> {
    let envelope = value.as_object().ok_or_else(|| {
        authority_error(
            D1WriteAuthorityClassification::CatalogResponseMalformed,
            "catalog readback did not contain the exact completeness envelope",
        )
    })?;
    if envelope.len() != 3
        || !envelope.contains_key("provider_row_cap")
        || !envelope.contains_key("results_truncated")
        || !envelope.contains_key("result")
    {
        return Err(authority_error(
            D1WriteAuthorityClassification::CatalogResponseMalformed,
            "catalog readback did not contain the exact completeness envelope",
        ));
    }
    if envelope.get("provider_row_cap").and_then(Value::as_u64)
        != Some(plan.required_provider_row_cap as u64)
    {
        return Err(authority_error(
            D1WriteAuthorityClassification::CatalogReadCapInsufficient,
            "catalog readback did not prove the plan-bound provider row capacity",
        ));
    }
    match envelope.get("results_truncated").and_then(Value::as_bool) {
        Some(false) => {}
        Some(true) => {
            return Err(authority_error(
                D1WriteAuthorityClassification::CatalogReadTruncated,
                "catalog readback reported truncated authority evidence",
            ));
        }
        None => {
            return Err(authority_error(
                D1WriteAuthorityClassification::CatalogResponseMalformed,
                "catalog readback did not contain a literal non-truncation marker",
            ));
        }
    }
    let result_sets = envelope
        .get("result")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            authority_error(
                D1WriteAuthorityClassification::CatalogResponseMalformed,
                "catalog readback did not contain one D1 result-set array",
            )
        })?;
    let [result_set] = result_sets.as_slice() else {
        return Err(authority_error(
            D1WriteAuthorityClassification::CatalogResponseMalformed,
            "catalog readback did not contain exactly one D1 result set",
        ));
    };
    let result_set = result_set.as_object().ok_or_else(|| {
        authority_error(
            D1WriteAuthorityClassification::CatalogResponseMalformed,
            "catalog result set was not an object",
        )
    })?;
    match result_set.get("results_truncated") {
        Some(Value::Bool(true)) => {
            return Err(authority_error(
                D1WriteAuthorityClassification::CatalogReadTruncated,
                "catalog readback reported truncated authority evidence",
            ));
        }
        Some(_) | None if result_set.contains_key("original_result_count") => {
            return Err(authority_error(
                D1WriteAuthorityClassification::CatalogResponseMalformed,
                "catalog result contained ambiguous row-limiter evidence",
            ));
        }
        Some(_) => {
            return Err(authority_error(
                D1WriteAuthorityClassification::CatalogResponseMalformed,
                "catalog result contained an unexpected truncation marker",
            ));
        }
        None => {}
    }
    if result_set.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(authority_error(
            D1WriteAuthorityClassification::CatalogResponseMalformed,
            "catalog result did not prove a successful inner D1 statement",
        ));
    }
    match result_set.get("errors") {
        None => {}
        Some(Value::Array(errors)) if errors.is_empty() => {}
        _ => {
            return Err(authority_error(
                D1WriteAuthorityClassification::CatalogResponseMalformed,
                "catalog result contained error or malformed error evidence",
            ));
        }
    }
    let meta = result_set
        .get("meta")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            authority_error(
                D1WriteAuthorityClassification::CatalogResponseMalformed,
                "catalog result did not contain typed read metadata",
            )
        })?;
    if meta.get("served_by_primary").and_then(Value::as_bool) != Some(true) {
        return Err(authority_error(
            D1WriteAuthorityClassification::CatalogReadNotPrimary,
            "catalog readback did not prove primary service",
        ));
    }
    if meta.get("changed_db").and_then(Value::as_bool) != Some(false)
        || meta.get("changes").and_then(Value::as_u64) != Some(0)
        || meta.get("rows_written").and_then(Value::as_u64) != Some(0)
    {
        return Err(authority_error(
            D1WriteAuthorityClassification::CatalogReadReportedMutation,
            "catalog readback did not prove exact read-only metadata",
        ));
    }
    let rows = result_set
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            authority_error(
                D1WriteAuthorityClassification::CatalogResponseMalformed,
                "catalog result did not contain a results array",
            )
        })?;
    if rows.len() > D1_WRITE_CATALOG_MAX_OBJECTS {
        return Err(authority_error(
            D1WriteAuthorityClassification::CatalogObjectLimitExceeded,
            "catalog inventory reached the bounded sentinel row",
        ));
    }
    let mut parsed_rows = Vec::with_capacity(rows.len());
    let mut total_sql_bytes = 0usize;
    for row in rows {
        let row = row.as_object().ok_or_else(|| {
            authority_error(
                D1WriteAuthorityClassification::CatalogResponseMalformed,
                "catalog row was not an object",
            )
        })?;
        if row.len() != 4 {
            return Err(authority_error(
                D1WriteAuthorityClassification::CatalogResponseMalformed,
                "catalog row did not have the exact fixed-query shape",
            ));
        }
        let text = |field: &str| {
            row.get(field)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| {
                    authority_error(
                        D1WriteAuthorityClassification::CatalogRowNonText,
                        "catalog identity or schema evidence was not TEXT",
                    )
                })
        };
        let parsed = CatalogRow {
            object_type: text("type")?,
            name: text("name")?,
            parent_name: text("tbl_name")?,
            sql: text("sql")?,
        };
        total_sql_bytes = total_sql_bytes
            .checked_add(parsed.sql.len())
            .ok_or_else(|| catalog_schema_malformed())?;
        if total_sql_bytes > D1_WRITE_CATALOG_SQL_MAX_BYTES {
            return Err(authority_error(
                D1WriteAuthorityClassification::CatalogObjectLimitExceeded,
                "catalog SQL evidence exceeded the bounded authority input",
            ));
        }
        parsed_rows.push(parsed);
    }
    parsed_rows.sort();
    build_catalog_snapshot(parsed_rows)
}

fn build_catalog_snapshot(rows: Vec<CatalogRow>) -> Result<CatalogSnapshot, D1WriteAuthorityError> {
    let mut object_identities = BTreeSet::new();
    let mut relations = BTreeMap::new();
    let mut parsed_triggers = Vec::new();
    for row in &rows {
        validate_catalog_text(&row.name)?;
        validate_catalog_text(&row.parent_name)?;
        if !object_identities.insert((row.object_type.clone(), ascii_identity(&row.name))) {
            return Err(authority_error(
                D1WriteAuthorityClassification::CatalogRowDuplicate,
                "catalog object identities collided under SQLite ASCII identity",
            ));
        }
        match row.object_type.as_str() {
            "table" | "view" => {
                if ascii_identity(&row.name) != ascii_identity(&row.parent_name) {
                    return Err(catalog_schema_malformed());
                }
                let kind = if row.object_type == "table" {
                    RelationKind::Table
                } else {
                    RelationKind::View
                };
                let (autoincrement, foreign_keys) =
                    validate_relation_schema(&row.sql, &row.name, &kind)
                        .map_err(|_| catalog_schema_malformed())?;
                if relations
                    .insert(
                        ascii_identity(&row.name),
                        Relation {
                            kind,
                            exact_name: row.name.clone(),
                            sql: row.sql.clone(),
                            autoincrement,
                            foreign_keys,
                        },
                    )
                    .is_some()
                {
                    return Err(authority_error(
                        D1WriteAuthorityClassification::CatalogRowDuplicate,
                        "table and view identities collided under SQLite ASCII identity",
                    ));
                }
            }
            "trigger" => {
                parsed_triggers.push((
                    ascii_identity(&row.parent_name),
                    parse_trigger(row).map_err(|_| catalog_schema_malformed())?,
                ));
            }
            _ => return Err(catalog_schema_malformed()),
        }
    }
    let mut triggers_by_parent: BTreeMap<String, Vec<Trigger>> = BTreeMap::new();
    for (parent, trigger) in parsed_triggers {
        let relation = relations
            .get(&parent)
            .ok_or_else(catalog_schema_malformed)?;
        match (&relation.kind, trigger.timing) {
            (RelationKind::Table, TriggerTiming::Before | TriggerTiming::After)
            | (RelationKind::View, TriggerTiming::InsteadOf) => {}
            _ => return Err(catalog_schema_malformed()),
        }
        triggers_by_parent.entry(parent).or_default().push(trigger);
    }
    let mut implicit_writes_by_parent: BTreeMap<
        (String, TriggerEvent),
        Vec<(String, TriggerEvent)>,
    > = BTreeMap::new();
    for (child_identity, relation) in &relations {
        for foreign_key in &relation.foreign_keys {
            let parent = relations
                .get(&foreign_key.parent_relation)
                .ok_or_else(catalog_schema_malformed)?;
            if parent.kind != RelationKind::Table {
                return Err(catalog_schema_malformed());
            }
            if let Some(child_event) = foreign_key
                .on_delete
                .child_write_event(TriggerEvent::Delete)
            {
                implicit_writes_by_parent
                    .entry((foreign_key.parent_relation.clone(), TriggerEvent::Delete))
                    .or_default()
                    .push((child_identity.clone(), child_event));
            }
            if let Some(child_event) = foreign_key
                .on_update
                .child_write_event(TriggerEvent::Update)
            {
                implicit_writes_by_parent
                    .entry((foreign_key.parent_relation.clone(), TriggerEvent::Update))
                    .or_default()
                    .push((child_identity.clone(), child_event));
            }
        }
    }
    for effects in implicit_writes_by_parent.values_mut() {
        effects.sort();
        effects.dedup();
    }
    Ok(CatalogSnapshot {
        rows,
        relations,
        triggers_by_parent,
        implicit_writes_by_parent,
    })
}

impl ForeignKeyAction {
    fn child_write_event(self, parent_event: TriggerEvent) -> Option<TriggerEvent> {
        match (self, parent_event) {
            (Self::Cascade, TriggerEvent::Delete) => Some(TriggerEvent::Delete),
            (Self::Cascade | Self::SetNull | Self::SetDefault, _) => Some(TriggerEvent::Update),
            (Self::NoAction | Self::Restrict, _) => None,
        }
    }
}

fn validate_catalog_text(value: &str) -> Result<(), D1WriteAuthorityError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(catalog_schema_malformed());
    }
    Ok(())
}

fn validate_relation_schema(
    sql: &str,
    expected_name: &str,
    kind: &RelationKind,
) -> Result<(bool, Vec<ForeignKeyDefinition>), D1WriteAuthorityError> {
    let tokens = one_statement_tokens(sql)?;
    let mut cursor = 0usize;
    require_word(&tokens, &mut cursor, "create")?;
    match kind {
        RelationKind::Table => require_word(&tokens, &mut cursor, "table")?,
        RelationKind::View => require_word(&tokens, &mut cursor, "view")?,
    }
    if token_is_word(tokens.get(cursor), "if") {
        require_word(&tokens, &mut cursor, "if")?;
        require_word(&tokens, &mut cursor, "not")?;
        require_word(&tokens, &mut cursor, "exists")?;
    }
    let (name, next) = relation_identifier(&tokens, cursor)?;
    if name != ascii_identity(expected_name) {
        return Err(catalog_schema_malformed());
    }
    if tokens.get(next) == Some(&SqlToken::Symbol('.')) {
        return Err(catalog_schema_malformed());
    }
    if kind == &RelationKind::View {
        if !token_is_word(tokens.get(next), "as") || next + 1 >= tokens.len() {
            return Err(catalog_schema_malformed());
        }
        return Ok((false, Vec::new()));
    }
    let Some(SqlToken::Symbol('(')) = tokens.get(next) else {
        return Err(catalog_schema_malformed());
    };
    let (segments, after_body) = table_definition_segments(&tokens, next)?;
    validate_table_options(&tokens[after_body..])?;
    let autoincrement = segments.iter().any(|segment| {
        segment
            .iter()
            .any(|token| token_is_word(Some(token), "autoincrement"))
    });
    let mut foreign_keys = Vec::new();
    for segment in segments {
        let references = segment
            .iter()
            .enumerate()
            .filter_map(|(index, token)| token_is_word(Some(token), "references").then_some(index))
            .collect::<Vec<_>>();
        if references.len() > 1 {
            return Err(catalog_schema_malformed());
        }
        let Some(reference_index) = references.first().copied() else {
            continue;
        };
        foreign_keys.push(parse_foreign_key_definition(segment, reference_index)?);
    }
    Ok((autoincrement, foreign_keys))
}

fn table_definition_segments(
    tokens: &[SqlToken],
    opening_parenthesis: usize,
) -> Result<(Vec<&[SqlToken]>, usize), D1WriteAuthorityError> {
    let mut segments = Vec::new();
    let mut depth = 1usize;
    let mut start = opening_parenthesis + 1;
    for (index, token) in tokens.iter().enumerate().skip(opening_parenthesis + 1) {
        match token {
            SqlToken::Symbol('(') => {
                depth = depth.checked_add(1).ok_or_else(catalog_schema_malformed)?;
            }
            SqlToken::Symbol(')') => {
                depth = depth.checked_sub(1).ok_or_else(catalog_schema_malformed)?;
                if depth == 0 {
                    if start == index {
                        return Err(catalog_schema_malformed());
                    }
                    segments.push(&tokens[start..index]);
                    return Ok((segments, index + 1));
                }
            }
            SqlToken::Symbol(',') if depth == 1 => {
                if start == index {
                    return Err(catalog_schema_malformed());
                }
                segments.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    Err(catalog_schema_malformed())
}

fn validate_table_options(tokens: &[SqlToken]) -> Result<(), D1WriteAuthorityError> {
    let mut cursor = 0usize;
    let mut strict_seen = false;
    let mut without_rowid_seen = false;
    while cursor < tokens.len() {
        if token_is_word(tokens.get(cursor), "strict") {
            if strict_seen {
                return Err(catalog_schema_malformed());
            }
            strict_seen = true;
            cursor += 1;
        } else if token_is_word(tokens.get(cursor), "without")
            && token_is_word(tokens.get(cursor + 1), "rowid")
        {
            if without_rowid_seen {
                return Err(catalog_schema_malformed());
            }
            without_rowid_seen = true;
            cursor += 2;
        } else {
            return Err(catalog_schema_malformed());
        }
        if cursor == tokens.len() {
            break;
        }
        if tokens.get(cursor) != Some(&SqlToken::Symbol(',')) || cursor + 1 == tokens.len() {
            return Err(catalog_schema_malformed());
        }
        cursor += 1;
    }
    Ok(())
}

fn parse_foreign_key_definition(
    segment: &[SqlToken],
    reference_index: usize,
) -> Result<ForeignKeyDefinition, D1WriteAuthorityError> {
    let (parent_relation, next) = relation_identifier(segment, reference_index + 1)?;
    if segment.get(next) == Some(&SqlToken::Symbol('.')) {
        return Err(catalog_schema_malformed());
    }
    let mut on_delete = ForeignKeyAction::NoAction;
    let mut on_update = ForeignKeyAction::NoAction;
    let mut delete_seen = false;
    let mut update_seen = false;
    let mut cursor = if segment.get(next) == Some(&SqlToken::Symbol('(')) {
        parse_identifier_list(segment, next)?
    } else {
        next
    };
    while cursor < segment.len() {
        if !token_is_word(segment.get(cursor), "on") {
            return Err(catalog_schema_malformed());
        }
        let (slot, seen) = if token_is_word(segment.get(cursor + 1), "delete") {
            (&mut on_delete, &mut delete_seen)
        } else if token_is_word(segment.get(cursor + 1), "update") {
            (&mut on_update, &mut update_seen)
        } else {
            return Err(catalog_schema_malformed());
        };
        if *seen {
            return Err(catalog_schema_malformed());
        }
        *seen = true;
        let (action, consumed) = parse_foreign_key_action(&segment[cursor + 2..])?;
        *slot = action;
        cursor += 2 + consumed;
    }
    Ok(ForeignKeyDefinition {
        parent_relation,
        on_delete,
        on_update,
    })
}

fn parse_identifier_list(
    tokens: &[SqlToken],
    opening_parenthesis: usize,
) -> Result<usize, D1WriteAuthorityError> {
    let mut cursor = opening_parenthesis + 1;
    loop {
        let (_, next) = relation_identifier(tokens, cursor)?;
        cursor = next;
        match tokens.get(cursor) {
            Some(SqlToken::Symbol(',')) => cursor += 1,
            Some(SqlToken::Symbol(')')) => return Ok(cursor + 1),
            _ => return Err(catalog_schema_malformed()),
        }
    }
}

fn parse_foreign_key_action(
    tokens: &[SqlToken],
) -> Result<(ForeignKeyAction, usize), D1WriteAuthorityError> {
    if token_is_word(tokens.first(), "cascade") {
        Ok((ForeignKeyAction::Cascade, 1))
    } else if token_is_word(tokens.first(), "restrict") {
        Ok((ForeignKeyAction::Restrict, 1))
    } else if token_is_word(tokens.first(), "no") && token_is_word(tokens.get(1), "action") {
        Ok((ForeignKeyAction::NoAction, 2))
    } else if token_is_word(tokens.first(), "set") && token_is_word(tokens.get(1), "null") {
        Ok((ForeignKeyAction::SetNull, 2))
    } else if token_is_word(tokens.first(), "set") && token_is_word(tokens.get(1), "default") {
        Ok((ForeignKeyAction::SetDefault, 2))
    } else {
        Err(catalog_schema_malformed())
    }
}

fn parse_trigger(row: &CatalogRow) -> Result<Trigger, D1WriteAuthorityError> {
    let tokens = trigger_schema_tokens(&row.sql)?;
    let mut cursor = 0usize;
    require_word(&tokens, &mut cursor, "create")?;
    require_word(&tokens, &mut cursor, "trigger")?;
    if token_is_word(tokens.get(cursor), "if") {
        require_word(&tokens, &mut cursor, "if")?;
        require_word(&tokens, &mut cursor, "not")?;
        require_word(&tokens, &mut cursor, "exists")?;
    }
    let (name, next) = relation_identifier(&tokens, cursor)?;
    if name != ascii_identity(&row.name) || tokens.get(next) == Some(&SqlToken::Symbol('.')) {
        return Err(catalog_schema_malformed());
    }
    cursor = next;
    let timing = if token_is_word(tokens.get(cursor), "before") {
        cursor += 1;
        TriggerTiming::Before
    } else if token_is_word(tokens.get(cursor), "after") {
        cursor += 1;
        TriggerTiming::After
    } else if token_is_word(tokens.get(cursor), "instead") {
        cursor += 1;
        require_word(&tokens, &mut cursor, "of")?;
        TriggerTiming::InsteadOf
    } else {
        TriggerTiming::Before
    };
    let event = if token_is_word(tokens.get(cursor), "insert") {
        cursor += 1;
        TriggerEvent::Insert
    } else if token_is_word(tokens.get(cursor), "delete") {
        cursor += 1;
        TriggerEvent::Delete
    } else if token_is_word(tokens.get(cursor), "update") {
        cursor += 1;
        if token_is_word(tokens.get(cursor), "of") {
            cursor += 1;
            let mut columns = 0usize;
            loop {
                let (_, next) = relation_identifier(&tokens, cursor)?;
                columns += 1;
                cursor = next;
                if tokens.get(cursor) == Some(&SqlToken::Symbol(',')) {
                    cursor += 1;
                    continue;
                }
                break;
            }
            if columns == 0 {
                return Err(catalog_schema_malformed());
            }
        }
        TriggerEvent::Update
    } else {
        return Err(catalog_schema_malformed());
    };
    require_word(&tokens, &mut cursor, "on")?;
    let (parent, next) = relation_identifier(&tokens, cursor)?;
    if parent != ascii_identity(&row.parent_name)
        || tokens.get(next) == Some(&SqlToken::Symbol('.'))
    {
        return Err(catalog_schema_malformed());
    }
    cursor = next;
    let begin =
        top_level_word_position(&tokens, cursor, "begin").ok_or_else(catalog_schema_malformed)?;
    let end = tokens
        .len()
        .checked_sub(1)
        .ok_or_else(catalog_schema_malformed)?;
    if !token_is_word(tokens.get(end), "end") || begin + 1 >= end {
        return Err(catalog_schema_malformed());
    }
    let statements = split_trigger_body(&tokens[begin + 1..end])?;
    let mut effects = Vec::new();
    for statement in statements {
        if token_is_word(statement.first(), "select") {
            continue;
        }
        effects.push(parse_dml_tokens(statement)?);
    }
    Ok(Trigger {
        timing,
        event,
        effects,
    })
}

fn split_trigger_body(tokens: &[SqlToken]) -> Result<Vec<&[SqlToken]>, D1WriteAuthorityError> {
    let mut statements = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut case_depth = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            SqlToken::Symbol('(') => {
                paren_depth = paren_depth
                    .checked_add(1)
                    .ok_or_else(catalog_schema_malformed)?
            }
            SqlToken::Symbol(')') => {
                paren_depth = paren_depth
                    .checked_sub(1)
                    .ok_or_else(catalog_schema_malformed)?
            }
            SqlToken::Word(word) if word.eq_ignore_ascii_case("case") => {
                case_depth = case_depth
                    .checked_add(1)
                    .ok_or_else(catalog_schema_malformed)?;
            }
            SqlToken::Word(word) if word.eq_ignore_ascii_case("end") && case_depth > 0 => {
                case_depth -= 1
            }
            SqlToken::Symbol(';') if paren_depth == 0 && case_depth == 0 => {
                if start == index {
                    return Err(catalog_schema_malformed());
                }
                statements.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if paren_depth != 0 || case_depth != 0 {
        return Err(catalog_schema_malformed());
    }
    if start < tokens.len() {
        statements.push(&tokens[start..]);
    }
    if statements.is_empty() {
        return Err(catalog_schema_malformed());
    }
    Ok(statements)
}

fn validate_configured_ledgers(
    snapshot: &CatalogSnapshot,
    configured_ledgers: &BTreeMap<String, String>,
) -> Result<(), D1WriteAuthorityError> {
    for (identity, exact_name) in configured_ledgers {
        let relation = snapshot.relations.get(identity).ok_or_else(|| {
            authority_error(
                D1WriteAuthorityClassification::ConfiguredLedgerAbsent,
                "a configured migration ledger was absent from the stable catalog",
            )
        })?;
        if relation.kind != RelationKind::Table
            || relation.exact_name != *exact_name
            || !is_supported_d1_migration_ledger_table_sql(&relation.sql, exact_name)
            || snapshot.triggers_by_parent.contains_key(identity)
        {
            return Err(authority_error(
                D1WriteAuthorityClassification::ConfiguredLedgerSchemaDrift,
                "a configured migration ledger did not retain its exact trigger-free schema authority",
            ));
        }
    }
    Ok(())
}

fn prove_reachability(
    plan: &D1WriteCatalogAuthorityPlan,
    snapshot: &CatalogSnapshot,
) -> Result<usize, D1WriteAuthorityError> {
    let mut queue = VecDeque::new();
    for event in &plan.trigger_events {
        queue.push_back((plan.target_relation.clone(), *event));
    }
    let mut visited = BTreeSet::new();
    let mut reachable_relations = BTreeSet::new();
    while let Some((relation_name, event)) = queue.pop_front() {
        if is_reserved_relation(&relation_name, &plan.configured_ledgers) {
            return Err(authority_error(
                D1WriteAuthorityClassification::ReservedRelationReachable,
                "catalog-proven DML reachability entered a reserved relation",
            ));
        }
        if !visited.insert((relation_name.clone(), event)) {
            continue;
        }
        reachable_relations.insert(relation_name.clone());
        let relation = snapshot.relations.get(&relation_name).ok_or_else(|| {
            authority_error(
                D1WriteAuthorityClassification::TargetRelationAbsent,
                "a direct or trigger-mediated DML target was absent from the stable catalog",
            )
        })?;
        if relation.autoincrement && event == TriggerEvent::Insert {
            return Err(authority_error(
                D1WriteAuthorityClassification::ReservedRelationReachable,
                "catalog-proven DML reachability entered a reserved relation",
            ));
        }
        let matching = snapshot
            .triggers_by_parent
            .get(&relation_name)
            .into_iter()
            .flatten()
            .filter(|trigger| trigger.event == event)
            .collect::<Vec<_>>();
        if relation.kind == RelationKind::View && matching.is_empty() {
            return Err(authority_error(
                D1WriteAuthorityClassification::ViewMutationUnproven,
                "a view DML target had no exact matching INSTEAD OF trigger authority",
            ));
        }
        for trigger in matching {
            for effect in &trigger.effects {
                for nested_event in &effect.trigger_events {
                    queue.push_back((effect.target_relation.clone(), *nested_event));
                }
            }
        }
        if let Some(implicit_writes) = snapshot
            .implicit_writes_by_parent
            .get(&(relation_name.clone(), event))
        {
            for (child_relation, child_event) in implicit_writes {
                queue.push_back((child_relation.clone(), *child_event));
            }
        }
    }
    Ok(reachable_relations.len())
}

fn parse_one_dml(sql: &str) -> Result<ParsedDml, D1WriteAuthorityError> {
    let tokens = one_statement_tokens(sql)?;
    parse_dml_tokens(&tokens)
}

fn trigger_schema_tokens(sql: &str) -> Result<Vec<SqlToken>, D1WriteAuthorityError> {
    let mut tokens = tokenize_sql(sql)?;
    if tokens.last() == Some(&SqlToken::Symbol(';')) {
        tokens.pop();
    }
    if tokens.is_empty() {
        return Err(catalog_schema_malformed());
    }
    Ok(tokens)
}

fn one_statement_tokens(sql: &str) -> Result<Vec<SqlToken>, D1WriteAuthorityError> {
    let mut tokens = tokenize_sql(sql)?;
    let semicolons = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| (token == &SqlToken::Symbol(';')).then_some(index))
        .collect::<Vec<_>>();
    match semicolons.as_slice() {
        [] => {}
        [index] if *index + 1 == tokens.len() => {
            tokens.pop();
        }
        _ => {
            return Err(authority_error(
                D1WriteAuthorityClassification::SqlMultipleStatements,
                "exactly one D1 DML statement is required",
            ));
        }
    }
    if tokens.is_empty() {
        return Err(authority_error(
            D1WriteAuthorityClassification::SqlMalformedOrUnsupported,
            "D1 DML did not contain a supported statement",
        ));
    }
    Ok(tokens)
}

fn parse_dml_tokens(tokens: &[SqlToken]) -> Result<ParsedDml, D1WriteAuthorityError> {
    let mut cursor = 0usize;
    let mut conflict_replace = false;
    let statement_kind;
    if token_is_word(tokens.get(cursor), "insert") {
        statement_kind = D1WriteStatementKind::Insert;
        cursor += 1;
        conflict_replace = parse_optional_conflict(tokens, &mut cursor)?;
        require_word(tokens, &mut cursor, "into")?;
    } else if token_is_word(tokens.get(cursor), "replace") {
        statement_kind = D1WriteStatementKind::Replace;
        conflict_replace = true;
        cursor += 1;
        require_word(tokens, &mut cursor, "into")?;
    } else if token_is_word(tokens.get(cursor), "update") {
        statement_kind = D1WriteStatementKind::Update;
        cursor += 1;
        conflict_replace = parse_optional_conflict(tokens, &mut cursor)?;
    } else if token_is_word(tokens.get(cursor), "delete") {
        statement_kind = D1WriteStatementKind::Delete;
        cursor += 1;
        require_word(tokens, &mut cursor, "from")?;
    } else {
        return Err(authority_error(
            D1WriteAuthorityClassification::SqlMalformedOrUnsupported,
            "D1 write authority accepts only INSERT, UPDATE, DELETE, or REPLACE",
        ));
    }
    let (target_relation, next) = relation_identifier(tokens, cursor)?;
    if tokens.get(next) == Some(&SqlToken::Symbol('.')) {
        return Err(authority_error(
            D1WriteAuthorityClassification::SqlSchemaQualifiedTarget,
            "schema-qualified D1 DML targets are not admitted",
        ));
    }
    let mut trigger_events = match statement_kind {
        D1WriteStatementKind::Insert => vec![TriggerEvent::Insert],
        D1WriteStatementKind::Update => vec![TriggerEvent::Update],
        D1WriteStatementKind::Delete => vec![TriggerEvent::Delete],
        D1WriteStatementKind::Replace => vec![TriggerEvent::Insert, TriggerEvent::Delete],
    };
    if conflict_replace && !trigger_events.contains(&TriggerEvent::Delete) {
        trigger_events.push(TriggerEvent::Delete);
    }
    if statement_kind == D1WriteStatementKind::Insert
        && tokens.windows(2).any(|window| {
            token_is_word(window.first(), "do") && token_is_word(window.get(1), "update")
        })
    {
        trigger_events.push(TriggerEvent::Update);
    }
    trigger_events.sort();
    trigger_events.dedup();
    Ok(ParsedDml {
        statement_kind,
        target_relation,
        trigger_events,
    })
}

fn parse_optional_conflict(
    tokens: &[SqlToken],
    cursor: &mut usize,
) -> Result<bool, D1WriteAuthorityError> {
    if !token_is_word(tokens.get(*cursor), "or") {
        return Ok(false);
    }
    *cursor += 1;
    let Some(SqlToken::Word(mode)) = tokens.get(*cursor) else {
        return Err(sql_malformed());
    };
    if !matches!(
        mode.to_ascii_lowercase().as_str(),
        "rollback" | "abort" | "fail" | "ignore" | "replace"
    ) {
        return Err(sql_malformed());
    }
    *cursor += 1;
    Ok(mode.eq_ignore_ascii_case("replace"))
}

fn relation_identifier(
    tokens: &[SqlToken],
    index: usize,
) -> Result<(String, usize), D1WriteAuthorityError> {
    let value = match tokens.get(index) {
        Some(SqlToken::Word(value) | SqlToken::Identifier(value)) => value,
        _ => return Err(sql_malformed()),
    };
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control() || !byte.is_ascii())
    {
        return Err(sql_malformed());
    }
    Ok((ascii_identity(value), index + 1))
}

fn require_word(
    tokens: &[SqlToken],
    cursor: &mut usize,
    expected: &str,
) -> Result<(), D1WriteAuthorityError> {
    if !token_is_word(tokens.get(*cursor), expected) {
        return Err(sql_malformed());
    }
    *cursor += 1;
    Ok(())
}

fn top_level_word_position(tokens: &[SqlToken], start: usize, expected: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token {
            SqlToken::Symbol('(') => depth += 1,
            SqlToken::Symbol(')') => depth = depth.checked_sub(1)?,
            _ if depth == 0 && token_is_word(Some(token), expected) => return Some(index),
            _ => {}
        }
    }
    None
}

fn tokenize_sql(sql: &str) -> Result<Vec<SqlToken>, D1WriteAuthorityError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
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
    let mut tokens = Vec::new();
    let mut current = Vec::new();
    let mut quoted = Vec::new();
    let mut index = 0usize;
    let flush = |current: &mut Vec<u8>, tokens: &mut Vec<SqlToken>| {
        if !current.is_empty() {
            tokens.push(SqlToken::Word(
                String::from_utf8_lossy(current).into_owned(),
            ));
            current.clear();
        }
    };
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match mode {
            Mode::Normal => match (byte, next) {
                (b'-', Some(b'-')) => {
                    flush(&mut current, &mut tokens);
                    mode = Mode::LineComment;
                    index += 1;
                }
                (b'/', Some(b'*')) => {
                    flush(&mut current, &mut tokens);
                    mode = Mode::BlockComment;
                    index += 1;
                }
                (b'\'', _) => {
                    flush(&mut current, &mut tokens);
                    quoted.clear();
                    mode = Mode::SingleQuote;
                }
                (b'"', _) => {
                    flush(&mut current, &mut tokens);
                    quoted.clear();
                    mode = Mode::DoubleQuote;
                }
                (b'`', _) => {
                    flush(&mut current, &mut tokens);
                    quoted.clear();
                    mode = Mode::Backtick;
                }
                (b'[', _) => {
                    flush(&mut current, &mut tokens);
                    quoted.clear();
                    mode = Mode::Bracket;
                }
                _ if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$') => {
                    current.push(byte)
                }
                _ if byte.is_ascii_whitespace() => flush(&mut current, &mut tokens),
                _ if byte.is_ascii_punctuation() => {
                    flush(&mut current, &mut tokens);
                    tokens.push(SqlToken::Symbol(byte as char));
                }
                _ => return Err(sql_malformed()),
            },
            Mode::SingleQuote => {
                if byte == b'\'' {
                    if next == Some(b'\'') {
                        quoted.push(b'\'');
                        index += 1;
                    } else {
                        String::from_utf8(quoted.clone()).map_err(|_| sql_malformed())?;
                        tokens.push(SqlToken::StringLiteral);
                        mode = Mode::Normal;
                    }
                } else {
                    quoted.push(byte);
                }
            }
            Mode::DoubleQuote | Mode::Backtick => {
                let delimiter = if mode == Mode::DoubleQuote {
                    b'"'
                } else {
                    b'`'
                };
                if byte == delimiter {
                    if next == Some(delimiter) {
                        quoted.push(delimiter);
                        index += 1;
                    } else {
                        tokens.push(SqlToken::Identifier(
                            String::from_utf8(quoted.clone()).map_err(|_| sql_malformed())?,
                        ));
                        mode = Mode::Normal;
                    }
                } else {
                    quoted.push(byte);
                }
            }
            Mode::Bracket => {
                if byte == b']' {
                    if next == Some(b']') {
                        quoted.push(b']');
                        index += 1;
                    } else {
                        tokens.push(SqlToken::Identifier(
                            String::from_utf8(quoted.clone()).map_err(|_| sql_malformed())?,
                        ));
                        mode = Mode::Normal;
                    }
                } else {
                    quoted.push(byte);
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
        return Err(sql_malformed());
    }
    flush(&mut current, &mut tokens);
    Ok(tokens)
}

fn token_is_word(token: Option<&SqlToken>, expected: &str) -> bool {
    matches!(token, Some(SqlToken::Word(word)) if word.eq_ignore_ascii_case(expected))
}

fn is_reserved_relation(identity: &str, configured_ledgers: &BTreeMap<String, String>) -> bool {
    is_reserved_family(identity) || configured_ledgers.contains_key(identity)
}

fn is_reserved_family(identity: &str) -> bool {
    let identity = ascii_identity(identity);
    identity.starts_with("sqlite_") || identity.starts_with("_cf_")
}

fn ascii_identity(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn sql_malformed() -> D1WriteAuthorityError {
    authority_error(
        D1WriteAuthorityClassification::SqlMalformedOrUnsupported,
        "SQL or catalog SQL could not be classified under the closed D1 DML grammar",
    )
}

fn catalog_schema_malformed() -> D1WriteAuthorityError {
    authority_error(
        D1WriteAuthorityClassification::CatalogSchemaMalformed,
        "catalog rows did not form one closed table, view, and trigger authority graph",
    )
}

fn authority_error(
    classification: D1WriteAuthorityClassification,
    message: &'static str,
) -> D1WriteAuthorityError {
    D1WriteAuthorityError {
        code: "d1.write_catalog_authority_denied",
        classification,
        message,
    }
}

fn sha256_hex(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn hash_serialized<T: Serialize>(value: &T) -> String {
    sha256_hex(&serde_json::to_vec(value).expect("authority evidence serialization cannot fail"))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::d1_migration_manifest::d1_migrations_table_init_sql;

    const DATABASE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn target() -> D1TargetIdentity {
        normalize_d1_target("acct-1", DATABASE_ID).expect("canonical target")
    }

    fn installed_ledger_sql(name: &str) -> String {
        d1_migrations_table_init_sql(name)
            .strip_suffix(';')
            .expect("initializer terminator")
            .replacen("CREATE TABLE IF NOT EXISTS", "CREATE TABLE", 1)
    }

    fn row(object_type: &str, name: &str, parent_name: &str, sql: &str) -> Value {
        json!({
            "type": object_type,
            "name": name,
            "tbl_name": parent_name,
            "sql": sql,
        })
    }

    fn table(name: &str) -> Value {
        row(
            "table",
            name,
            name,
            &format!("CREATE TABLE \"{name}\"(id INTEGER PRIMARY KEY, value TEXT)"),
        )
    }

    fn table_sql(name: &str, sql: &str) -> Value {
        row("table", name, name, sql)
    }

    fn view(name: &str) -> Value {
        row(
            "view",
            name,
            name,
            &format!("CREATE VIEW \"{name}\" AS SELECT id, value FROM \"items\""),
        )
    }

    fn ledger(name: &str) -> Value {
        row("table", name, name, &installed_ledger_sql(name))
    }

    fn trigger(name: &str, parent: &str, sql: &str) -> Value {
        row("trigger", name, parent, sql)
    }

    fn safe_rows(ledger_name: &str) -> Vec<Value> {
        vec![ledger(ledger_name), table("items"), table("audit")]
    }

    fn response(rows: Vec<Value>) -> Value {
        json!({
            "provider_row_cap": D1_WRITE_CATALOG_REQUIRED_PROVIDER_ROW_CAP,
            "results_truncated": false,
            "result": [{
                "success": true,
                "errors": [],
                "results": rows,
                "meta": {
                    "served_by_primary": true,
                    "changed_db": false,
                    "changes": 0,
                    "rows_written": 0,
                }
            }]
        })
    }

    fn plan(sql: &str, ledgers: &[&str]) -> D1WriteCatalogAuthorityPlan {
        derive_d1_write_catalog_authority_plan(
            &target(),
            sql,
            &ledgers
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        )
        .expect("authority plan")
        .0
    }

    fn classification(
        plan: &D1WriteCatalogAuthorityPlan,
        first: &Value,
        second: &Value,
    ) -> D1WriteAuthorityClassification {
        authorize_d1_write_catalog(plan, first, second)
            .expect_err("fixture must fail closed")
            .classification
    }

    #[test]
    fn plan_binds_exact_target_sql_reserved_set_and_fixed_bounded_query() {
        let (baseline, baseline_hash, query) = derive_d1_write_catalog_authority_plan(
            &target(),
            "UPDATE items SET value = ? WHERE id = ?",
            &["d1_migrations".to_string()],
        )
        .expect("baseline plan");
        assert_eq!(baseline.version, 2);
        assert_eq!(baseline.target_key_sha256, target().target_key_sha256());
        assert_eq!(baseline.reserved_relation_count, 1);
        assert_eq!(baseline.max_catalog_objects, D1_WRITE_CATALOG_MAX_OBJECTS);
        assert_eq!(
            baseline.required_provider_row_cap,
            D1_WRITE_CATALOG_REQUIRED_PROVIDER_ROW_CAP
        );
        assert!(query.contains("FROM sqlite_master"));
        assert!(query.contains("LIMIT 1001"));
        assert_eq!(baseline.catalog_query_sha256, sha256_hex(query.as_bytes()));

        let (_, changed_sql, _) = derive_d1_write_catalog_authority_plan(
            &target(),
            "UPDATE items SET value = ? WHERE id = ? AND value <> ?",
            &["d1_migrations".to_string()],
        )
        .expect("changed SQL plan");
        let (_, changed_ledger, _) = derive_d1_write_catalog_authority_plan(
            &target(),
            "UPDATE items SET value = ? WHERE id = ?",
            &["custom_migrations".to_string()],
        )
        .expect("changed ledger plan");
        let other_target = normalize_d1_target("acct-1", "223e4567-e89b-42d3-a456-426614174000")
            .expect("other target");
        let (_, changed_target, _) = derive_d1_write_catalog_authority_plan(
            &other_target,
            "UPDATE items SET value = ? WHERE id = ?",
            &["d1_migrations".to_string()],
        )
        .expect("changed target plan");
        assert_ne!(baseline_hash, changed_sql);
        assert_ne!(baseline_hash, changed_ledger);
        assert_ne!(baseline_hash, changed_target);

        let invalid_target = D1TargetIdentity {
            account_id: " acct-1".to_string(),
            database_id: DATABASE_ID.to_string(),
        };
        let error = derive_d1_write_catalog_authority_plan(
            &invalid_target,
            "UPDATE items SET value = 1",
            &["d1_migrations".to_string()],
        )
        .expect_err("typed target cannot bypass canonical identity readback");
        assert_eq!(
            error.classification,
            D1WriteAuthorityClassification::TargetIdentityInvalid
        );
    }

    #[test]
    fn direct_and_quoted_reserved_targets_fail_before_catalog_authority() {
        for sql in [
            "DELETE FROM d1_migrations",
            "DELETE FROM \"D1_MIGRATIONS\"",
            "UPDATE [d1_migrations] SET name = 'x'",
            "INSERT INTO `d1_migrations`(name) VALUES ('x')",
            "DELETE FROM custom_ledger",
            "DELETE FROM sqlite_sequence",
            "UPDATE \"_CF_KV\" SET value = 'x'",
        ] {
            let error = derive_d1_write_catalog_authority_plan(
                &target(),
                sql,
                &["d1_migrations".to_string(), "custom_ledger".to_string()],
            )
            .expect_err(sql);
            assert_eq!(
                error.classification,
                D1WriteAuthorityClassification::ReservedRelationTarget,
                "{sql}"
            );
        }
    }

    #[test]
    fn malformed_multi_statement_and_schema_qualified_dml_fail_closed() {
        let cases = [
            (
                "UPDATE items SET value = 1; DELETE FROM audit",
                D1WriteAuthorityClassification::SqlMultipleStatements,
            ),
            (
                "UPDATE main.items SET value = 1",
                D1WriteAuthorityClassification::SqlSchemaQualifiedTarget,
            ),
            (
                "WITH changed AS (SELECT 1) UPDATE items SET value = 1",
                D1WriteAuthorityClassification::SqlMalformedOrUnsupported,
            ),
            (
                "UPDATE \"unterminated SET value = 1",
                D1WriteAuthorityClassification::SqlMalformedOrUnsupported,
            ),
        ];
        for (sql, expected) in cases {
            let error = derive_d1_write_catalog_authority_plan(
                &target(),
                sql,
                &["d1_migrations".to_string()],
            )
            .expect_err(sql);
            assert_eq!(error.classification, expected, "{sql}");
        }
    }

    #[test]
    fn configured_ledger_inputs_are_exact_and_unaliased() {
        for ledgers in [
            Vec::<String>::new(),
            vec![" d1_migrations".to_string()],
            vec!["sqlite_ledger".to_string()],
            vec!["_cf_ledger".to_string()],
        ] {
            let error = derive_d1_write_catalog_authority_plan(
                &target(),
                "UPDATE items SET value = 1",
                &ledgers,
            )
            .expect_err("invalid ledger set");
            assert_eq!(
                error.classification,
                D1WriteAuthorityClassification::ConfiguredLedgerInvalid
            );
        }
        let error = derive_d1_write_catalog_authority_plan(
            &target(),
            "UPDATE items SET value = 1",
            &["Ledger".to_string(), "ledger".to_string()],
        )
        .expect_err("case-equivalent duplicates");
        assert_eq!(
            error.classification,
            D1WriteAuthorityClassification::ConfiguredLedgerDuplicate
        );
    }

    #[test]
    fn stable_safe_table_and_quoted_target_are_authorized() {
        for sql in [
            "UPDATE items SET value = ? WHERE id = ?",
            "UPDATE \"ITEMS\" SET value = ? WHERE id = ?",
            "INSERT OR IGNORE INTO [items](id, value) VALUES (?, ?)",
        ] {
            let plan = plan(sql, &["d1_migrations"]);
            let catalog = response(safe_rows("d1_migrations"));
            let receipt = authorize_d1_write_catalog(&plan, &catalog, &catalog)
                .expect("safe stable table DML");
            assert_eq!(receipt.stable_primary_readbacks, 2);
            assert_eq!(receipt.reachable_relation_count, 1);
            assert_eq!(receipt.catalog_object_count, 3);
            assert_eq!(receipt.catalog_trigger_count, 0);
        }
    }

    #[test]
    fn table_schema_body_and_suffix_are_fully_consumed() {
        for sql in [
            "CREATE TABLE \"audit\" AS SELECT 1 AS id",
            "CREATE TABLE \"audit\"",
            "CREATE TABLE \"audit\"(id INTEGER PRIMARY KEY) UNKNOWN",
            "CREATE TABLE \"audit\"(id INTEGER PRIMARY KEY) AUTOINCREMENT",
            "CREATE TABLE \"audit\"(id INTEGER PRIMARY KEY) STRICT STRICT",
            "CREATE TABLE \"audit\"(id INTEGER PRIMARY KEY) WITHOUT ROWID STRICT",
            "CREATE TABLE \"audit\"(id INTEGER PRIMARY KEY) STRICT,",
            "CREATE TABLE \"audit\"(id INTEGER PRIMARY KEY) STRICT MALICIOUS;",
        ] {
            let catalog = response(vec![
                ledger("d1_migrations"),
                table("items"),
                table_sql("audit", sql),
            ]);
            let plan = plan("UPDATE items SET value = ?", &["d1_migrations"]);
            assert_eq!(
                classification(&plan, &catalog, &catalog),
                D1WriteAuthorityClassification::CatalogSchemaMalformed,
                "{sql}"
            );
        }

        for sql in [
            "CREATE TABLE \"items\"(id INTEGER PRIMARY KEY, value TEXT)",
            "CREATE TABLE \"items\"(id INTEGER PRIMARY KEY, value TEXT) STRICT",
            "CREATE TABLE \"items\"(id INTEGER PRIMARY KEY, value TEXT) WITHOUT ROWID",
            "CREATE TABLE \"items\"(id INTEGER PRIMARY KEY, value TEXT) STRICT, WITHOUT ROWID",
            "CREATE TABLE \"items\"(id INTEGER PRIMARY KEY, value TEXT) WITHOUT ROWID, STRICT;",
        ] {
            let catalog = response(vec![ledger("d1_migrations"), table_sql("items", sql)]);
            let plan = plan("UPDATE items SET value = ?", &["d1_migrations"]);
            authorize_d1_write_catalog(&plan, &catalog, &catalog)
                .expect("closed supported table option grammar");
        }
    }

    #[test]
    fn custom_configured_ledger_is_proven_and_protected() {
        let plan = plan("UPDATE items SET value = 1", &["custom_ledger"]);
        let catalog = response(safe_rows("custom_ledger"));
        authorize_d1_write_catalog(&plan, &catalog, &catalog)
            .expect("custom exact ledger schema is authority");
        let direct = derive_d1_write_catalog_authority_plan(
            &target(),
            "UPDATE custom_ledger SET name = 'x'",
            &["custom_ledger".to_string()],
        )
        .expect_err("custom ledger remains reserved");
        assert_eq!(
            direct.classification,
            D1WriteAuthorityClassification::ReservedRelationTarget
        );
    }

    #[test]
    fn before_and_after_trigger_chains_into_ledger_are_denied() {
        for timing in ["BEFORE", "AFTER"] {
            let mut rows = safe_rows("d1_migrations");
            rows.push(trigger(
                "items_to_audit",
                "items",
                &format!(
                    "CREATE TRIGGER \"items_to_audit\" {timing} INSERT ON \"items\" BEGIN INSERT INTO \"audit\"(id, value) VALUES (NEW.id, NEW.value); END"
                ),
            ));
            rows.push(trigger(
                "audit_to_ledger",
                "audit",
                "CREATE TRIGGER \"audit_to_ledger\" BEFORE INSERT ON \"audit\" BEGIN UPDATE \"d1_migrations\" SET name = name; END",
            ));
            let catalog = response(rows);
            let plan = plan(
                "INSERT INTO items(id, value) VALUES (?, ?)",
                &["d1_migrations"],
            );
            assert_eq!(
                classification(&plan, &catalog, &catalog),
                D1WriteAuthorityClassification::ReservedRelationReachable,
                "{timing}"
            );
        }
    }

    #[test]
    fn view_instead_of_trigger_is_followed_and_safe_view_is_supported() {
        let mut safe = safe_rows("d1_migrations");
        safe.push(view("items_view"));
        safe.push(trigger(
            "items_view_insert",
            "items_view",
            "CREATE TRIGGER \"items_view_insert\" INSTEAD OF INSERT ON \"items_view\" BEGIN INSERT INTO \"items\"(id, value) VALUES (NEW.id, NEW.value); END",
        ));
        let catalog = response(safe);
        let plan = plan(
            "INSERT INTO items_view(id, value) VALUES (?, ?)",
            &["d1_migrations"],
        );
        let receipt =
            authorize_d1_write_catalog(&plan, &catalog, &catalog).expect("safe view trigger graph");
        assert_eq!(receipt.reachable_relation_count, 2);

        let mut unsafe_rows = safe_rows("d1_migrations");
        unsafe_rows.push(view("items_view"));
        unsafe_rows.push(trigger(
            "items_view_insert",
            "items_view",
            "CREATE TRIGGER \"items_view_insert\" INSTEAD OF INSERT ON \"items_view\" BEGIN UPDATE \"d1_migrations\" SET name = name; END",
        ));
        let unsafe_catalog = response(unsafe_rows);
        assert_eq!(
            classification(&plan, &unsafe_catalog, &unsafe_catalog),
            D1WriteAuthorityClassification::ReservedRelationReachable
        );

        let no_trigger = response({
            let mut rows = safe_rows("d1_migrations");
            rows.push(view("items_view"));
            rows
        });
        assert_eq!(
            classification(&plan, &no_trigger, &no_trigger),
            D1WriteAuthorityClassification::ViewMutationUnproven
        );
    }

    #[test]
    fn replace_and_upsert_secondary_trigger_events_are_not_hidden() {
        let mut delete_rows = safe_rows("d1_migrations");
        delete_rows.push(trigger(
            "items_delete_ledger",
            "items",
            "CREATE TRIGGER \"items_delete_ledger\" AFTER DELETE ON \"items\" BEGIN UPDATE \"d1_migrations\" SET name = name; END",
        ));
        let delete_catalog = response(delete_rows);
        let replace = plan(
            "REPLACE INTO items(id, value) VALUES (?, ?)",
            &["d1_migrations"],
        );
        assert_eq!(
            classification(&replace, &delete_catalog, &delete_catalog),
            D1WriteAuthorityClassification::ReservedRelationReachable
        );

        let mut update_rows = safe_rows("d1_migrations");
        update_rows.push(trigger(
            "items_update_ledger",
            "items",
            "CREATE TRIGGER \"items_update_ledger\" AFTER UPDATE ON \"items\" BEGIN UPDATE \"d1_migrations\" SET name = name; END",
        ));
        let update_catalog = response(update_rows);
        let upsert = plan(
            "INSERT INTO items(id, value) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET value = excluded.value",
            &["d1_migrations"],
        );
        assert_eq!(
            classification(&upsert, &update_catalog, &update_catalog),
            D1WriteAuthorityClassification::ReservedRelationReachable
        );
    }

    #[test]
    fn unrelated_trigger_events_and_string_literals_do_not_create_false_edges() {
        let mut rows = safe_rows("d1_migrations");
        rows.push(trigger(
            "items",
            "items",
            "CREATE TRIGGER \"items\" AFTER DELETE ON \"items\" BEGIN SELECT 'd1_migrations'; END",
        ));
        let catalog = response(rows);
        let plan = plan(
            "INSERT INTO items(id, value) VALUES (?, ?)",
            &["d1_migrations"],
        );
        authorize_d1_write_catalog(&plan, &catalog, &catalog)
            .expect("unrelated event and literal are not write edges");
    }

    #[test]
    fn autoincrement_insert_and_replace_reach_sqlite_sequence() {
        let catalog = response(vec![
            ledger("d1_migrations"),
            table_sql(
                "items",
                "CREATE TABLE \"items\"(id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT)",
            ),
            table_sql("sqlite_sequence", "CREATE TABLE sqlite_sequence(name,seq)"),
        ]);
        for sql in [
            "INSERT INTO items(value) VALUES (?)",
            "REPLACE INTO items(id, value) VALUES (?, ?)",
        ] {
            let plan = plan(sql, &["d1_migrations"]);
            assert_eq!(
                classification(&plan, &catalog, &catalog),
                D1WriteAuthorityClassification::ReservedRelationReachable,
                "{sql}"
            );
        }

        let update = plan(
            "UPDATE items SET value = ? WHERE id = ?",
            &["d1_migrations"],
        );
        authorize_d1_write_catalog(&update, &catalog, &catalog)
            .expect("updates do not mutate sqlite_sequence");

        let quoted_keyword = response(vec![
            ledger("d1_migrations"),
            table_sql(
                "items",
                "CREATE TABLE \"items\"(id INTEGER PRIMARY KEY, \"AUTOINCREMENT\" TEXT)",
            ),
        ]);
        let insert = plan(
            "INSERT INTO items(id, \"AUTOINCREMENT\") VALUES (?, ?)",
            &["d1_migrations"],
        );
        authorize_d1_write_catalog(&insert, &quoted_keyword, &quoted_keyword)
            .expect("a quoted identifier is not the AUTOINCREMENT keyword");
    }

    #[test]
    fn mutating_foreign_key_actions_reach_reserved_children() {
        let cases = [
            ("DELETE FROM items WHERE id = ?", "ON DELETE CASCADE"),
            ("DELETE FROM items WHERE id = ?", "ON DELETE SET NULL"),
            ("DELETE FROM items WHERE id = ?", "ON DELETE SET DEFAULT"),
            ("UPDATE items SET id = ? WHERE id = ?", "ON UPDATE CASCADE"),
            ("UPDATE items SET id = ? WHERE id = ?", "ON UPDATE SET NULL"),
            (
                "UPDATE items SET id = ? WHERE id = ?",
                "ON UPDATE SET DEFAULT",
            ),
        ];
        for (sql, action) in cases {
            let catalog = response(vec![
                ledger("d1_migrations"),
                table("items"),
                table_sql(
                    "_cf_child",
                    &format!(
                        "CREATE TABLE \"_cf_child\"(id INTEGER PRIMARY KEY, parent_id INTEGER DEFAULT 1 REFERENCES \"items\"(id) {action})"
                    ),
                ),
            ]);
            let plan = plan(sql, &["d1_migrations"]);
            assert_eq!(
                classification(&plan, &catalog, &catalog),
                D1WriteAuthorityClassification::ReservedRelationReachable,
                "{action}"
            );
        }
    }

    #[test]
    fn foreign_key_cascade_enters_explicit_trigger_graph() {
        let catalog = response(vec![
            ledger("d1_migrations"),
            table("items"),
            table_sql(
                "audit",
                "CREATE TABLE \"audit\"(id INTEGER PRIMARY KEY, parent_id INTEGER, FOREIGN KEY(parent_id) REFERENCES \"items\"(id) ON DELETE CASCADE)",
            ),
            trigger(
                "audit_delete_ledger",
                "audit",
                "CREATE TRIGGER \"audit_delete_ledger\" AFTER DELETE ON \"audit\" BEGIN UPDATE \"d1_migrations\" SET name = name; END",
            ),
        ]);
        let plan = plan("DELETE FROM items WHERE id = ?", &["d1_migrations"]);
        assert_eq!(
            classification(&plan, &catalog, &catalog),
            D1WriteAuthorityClassification::ReservedRelationReachable
        );
    }

    #[test]
    fn restrict_and_no_action_foreign_keys_create_no_write_edge() {
        for action in [
            "ON DELETE RESTRICT ON UPDATE RESTRICT",
            "ON DELETE NO ACTION ON UPDATE NO ACTION",
            "",
        ] {
            let catalog = response(vec![
                ledger("d1_migrations"),
                table("items"),
                table_sql(
                    "_cf_child",
                    &format!(
                        "CREATE TABLE \"_cf_child\"(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES \"items\"(id) {action})"
                    ),
                ),
            ]);
            for sql in [
                "DELETE FROM items WHERE id = ?",
                "UPDATE items SET id = ? WHERE id = ?",
            ] {
                let plan = plan(sql, &["d1_migrations"]);
                authorize_d1_write_catalog(&plan, &catalog, &catalog)
                    .expect("constraint-only foreign-key action has no child write edge");
            }
        }
    }

    #[test]
    fn malformed_or_unresolved_foreign_key_authority_fails_closed() {
        for child_sql in [
            "CREATE TABLE \"audit\"(parent_id INTEGER REFERENCES \"items\"(id) ON DELETE CASCADE ON DELETE SET NULL)",
            "CREATE TABLE \"audit\"(parent_id INTEGER REFERENCES \"items\"(id) ON DELETE UNKNOWN)",
            "CREATE TABLE \"audit\"(parent_id INTEGER REFERENCES \"items\"(id) ON FOO CASCADE)",
            "CREATE TABLE \"audit\"(parent_id INTEGER REFERENCES \"items\"(id) ON DELETE CASCADE STRAY)",
            "CREATE TABLE \"audit\"(parent_id INTEGER REFERENCES \"items\"(id) MATCH simple)",
            "CREATE TABLE \"audit\"(parent_id INTEGER REFERENCES \"items\"(id) DEFERRABLE)",
            "CREATE TABLE \"audit\"(parent_id INTEGER REFERENCES main.items(id) ON DELETE CASCADE)",
            "CREATE TABLE \"audit\"(parent_id INTEGER REFERENCES \"missing\"(id) ON DELETE CASCADE)",
        ] {
            let catalog = response(vec![
                ledger("d1_migrations"),
                table("items"),
                table_sql("audit", child_sql),
            ]);
            let plan = plan("DELETE FROM items WHERE id = ?", &["d1_migrations"]);
            assert_eq!(
                classification(&plan, &catalog, &catalog),
                D1WriteAuthorityClassification::CatalogSchemaMalformed,
                "{child_sql}"
            );
        }
    }

    #[test]
    fn ledger_absence_schema_drift_and_ledger_triggers_fail_closed() {
        let plan = plan("UPDATE items SET value = 1", &["d1_migrations"]);
        let absent = response(vec![table("items")]);
        assert_eq!(
            classification(&plan, &absent, &absent),
            D1WriteAuthorityClassification::ConfiguredLedgerAbsent
        );

        let drifted = response(vec![
            row(
                "table",
                "d1_migrations",
                "d1_migrations",
                "CREATE TABLE \"d1_migrations\"(id INTEGER PRIMARY KEY, name TEXT)",
            ),
            table("items"),
        ]);
        assert_eq!(
            classification(&plan, &drifted, &drifted),
            D1WriteAuthorityClassification::ConfiguredLedgerSchemaDrift
        );

        let with_trigger = response(vec![
            ledger("d1_migrations"),
            table("items"),
            trigger(
                "ledger_trigger",
                "d1_migrations",
                "CREATE TRIGGER \"ledger_trigger\" AFTER INSERT ON \"d1_migrations\" BEGIN SELECT 1; END",
            ),
        ]);
        assert_eq!(
            classification(&plan, &with_trigger, &with_trigger),
            D1WriteAuthorityClassification::ConfiguredLedgerSchemaDrift
        );
    }

    #[test]
    fn duplicate_non_text_or_malformed_catalog_rows_fail_closed() {
        let plan = plan("UPDATE items SET value = 1", &["d1_migrations"]);
        let duplicate = response(vec![
            ledger("d1_migrations"),
            table("items"),
            row(
                "table",
                "ITEMS",
                "ITEMS",
                "CREATE TABLE \"ITEMS\"(id INTEGER PRIMARY KEY, value TEXT)",
            ),
        ]);
        assert_eq!(
            classification(&plan, &duplicate, &duplicate),
            D1WriteAuthorityClassification::CatalogRowDuplicate
        );

        let mut non_text_rows = safe_rows("d1_migrations");
        non_text_rows[1]["name"] = json!(7);
        let non_text = response(non_text_rows);
        assert_eq!(
            classification(&plan, &non_text, &non_text),
            D1WriteAuthorityClassification::CatalogRowNonText
        );

        let malformed = response(vec![
            ledger("d1_migrations"),
            table("items"),
            trigger(
                "orphan",
                "missing_parent",
                "CREATE TRIGGER \"orphan\" AFTER INSERT ON \"missing_parent\" BEGIN SELECT 1; END",
            ),
        ]);
        assert_eq!(
            classification(&plan, &malformed, &malformed),
            D1WriteAuthorityClassification::CatalogSchemaMalformed
        );
    }

    #[test]
    fn target_absence_and_catalog_drift_are_distinct_closed_states() {
        let plan = plan("UPDATE items SET value = 1", &["d1_migrations"]);
        let absent = response(vec![ledger("d1_migrations")]);
        assert_eq!(
            classification(&plan, &absent, &absent),
            D1WriteAuthorityClassification::TargetRelationAbsent
        );

        let first = response(safe_rows("d1_migrations"));
        let mut changed_rows = safe_rows("d1_migrations");
        changed_rows.push(table("new_table"));
        let second = response(changed_rows);
        assert_eq!(
            classification(&plan, &first, &second),
            D1WriteAuthorityClassification::CatalogReadbacksUnstable
        );
    }

    #[test]
    fn ambiguous_provider_and_catalog_readbacks_never_authorize() {
        let plan = plan("UPDATE items SET value = 1", &["d1_migrations"]);
        let valid = response(safe_rows("d1_migrations"));
        let mut cases = Vec::new();
        cases.push((
            Value::Null,
            D1WriteAuthorityClassification::CatalogResponseMalformed,
        ));
        cases.push((
            json!([]),
            D1WriteAuthorityClassification::CatalogResponseMalformed,
        ));
        cases.push((
            json!([{}, {}]),
            D1WriteAuthorityClassification::CatalogResponseMalformed,
        ));
        let mut failed = valid.clone();
        failed["result"][0]["success"] = json!(false);
        cases.push((
            failed,
            D1WriteAuthorityClassification::CatalogResponseMalformed,
        ));
        let mut errors = valid.clone();
        errors["result"][0]["errors"] = json!([{"message": "private provider detail"}]);
        cases.push((
            errors,
            D1WriteAuthorityClassification::CatalogResponseMalformed,
        ));
        let mut non_primary = valid.clone();
        non_primary["result"][0]["meta"]["served_by_primary"] = json!(false);
        cases.push((
            non_primary,
            D1WriteAuthorityClassification::CatalogReadNotPrimary,
        ));
        let mut mutating = valid.clone();
        mutating["result"][0]["meta"]["changed_db"] = json!(true);
        cases.push((
            mutating,
            D1WriteAuthorityClassification::CatalogReadReportedMutation,
        ));
        let mut missing_count = valid.clone();
        missing_count["result"][0]["meta"]
            .as_object_mut()
            .expect("meta")
            .remove("changes");
        cases.push((
            missing_count,
            D1WriteAuthorityClassification::CatalogReadReportedMutation,
        ));

        for (value, expected) in cases {
            let error = authorize_d1_write_catalog(&plan, &value, &value)
                .expect_err("ambiguous provider evidence");
            assert_eq!(error.classification, expected);
            let serialized = serde_json::to_string(&error).expect("aggregate-safe error");
            assert!(!serialized.contains("private provider detail"));
            assert!(!serialized.contains("d1_migrations"));
            assert!(!serialized.contains("items"));
        }
    }

    #[test]
    fn completeness_envelope_is_exact_and_cannot_use_the_generic_thousand_row_cap() {
        let plan = plan("UPDATE items SET value = 1", &["d1_migrations"]);
        let valid = response(safe_rows("d1_migrations"));

        let mut truncated = valid.clone();
        truncated["results_truncated"] = json!(true);
        assert_eq!(
            classification(&plan, &truncated, &truncated),
            D1WriteAuthorityClassification::CatalogReadTruncated
        );

        let mut nested_truncated = valid.clone();
        nested_truncated["result"][0]["results_truncated"] = json!(true);
        nested_truncated["result"][0]["original_result_count"] = json!(1001);
        assert_eq!(
            classification(&plan, &nested_truncated, &nested_truncated),
            D1WriteAuthorityClassification::CatalogReadTruncated
        );

        let mut non_boolean = valid.clone();
        non_boolean["results_truncated"] = json!("false");
        assert_eq!(
            classification(&plan, &non_boolean, &non_boolean),
            D1WriteAuthorityClassification::CatalogResponseMalformed
        );

        let mut missing = valid.clone();
        missing
            .as_object_mut()
            .expect("envelope")
            .remove("results_truncated");
        assert_eq!(
            classification(&plan, &missing, &missing),
            D1WriteAuthorityClassification::CatalogResponseMalformed
        );

        let mut generic_cap = valid.clone();
        generic_cap["provider_row_cap"] = json!(1000);
        assert_eq!(
            classification(&plan, &generic_cap, &generic_cap),
            D1WriteAuthorityClassification::CatalogReadCapInsufficient
        );

        let mut extra = valid.clone();
        extra["unexpected"] = json!(false);
        assert_eq!(
            classification(&plan, &extra, &extra),
            D1WriteAuthorityClassification::CatalogResponseMalformed
        );
    }

    #[test]
    fn one_thousand_rows_are_complete_but_a_truncated_late_row_is_never_hidden() {
        let plan = plan("UPDATE items SET value = 1", &["d1_migrations"]);
        let mut rows = vec![ledger("d1_migrations"), table("items")];
        for index in 0..(D1_WRITE_CATALOG_MAX_OBJECTS - rows.len()) {
            rows.push(table(&format!("safe_{index}")));
        }
        assert_eq!(rows.len(), D1_WRITE_CATALOG_MAX_OBJECTS);
        let complete = response(rows.clone());
        let receipt = authorize_d1_write_catalog(&plan, &complete, &complete)
            .expect("the full 1000-row catalog is below the sentinel");
        assert_eq!(receipt.catalog_object_count, D1_WRITE_CATALOG_MAX_OBJECTS);
        assert_eq!(
            receipt.provider_row_cap,
            D1_WRITE_CATALOG_REQUIRED_PROVIDER_ROW_CAP
        );

        rows.push(trigger(
            "zz_late_reserved_write",
            "items",
            "CREATE TRIGGER \"zz_late_reserved_write\" AFTER UPDATE ON \"items\" BEGIN UPDATE \"d1_migrations\" SET name = name; END",
        ));
        assert_eq!(
            rows.len(),
            D1_WRITE_CATALOG_REQUIRED_PROVIDER_ROW_CAP,
            "the generic cap would omit the late reserved-write trigger"
        );
        rows.truncate(D1_WRITE_CATALOG_MAX_OBJECTS);
        let mut late_reserved_or_trigger_row_omitted = response(rows);
        late_reserved_or_trigger_row_omitted["results_truncated"] = json!(true);
        assert_eq!(
            classification(
                &plan,
                &late_reserved_or_trigger_row_omitted,
                &late_reserved_or_trigger_row_omitted,
            ),
            D1WriteAuthorityClassification::CatalogReadTruncated
        );
    }

    #[test]
    fn catalog_sentinel_row_blocks_instead_of_truncating_authority() {
        let plan = plan("UPDATE items SET value = 1", &["d1_migrations"]);
        let mut rows = vec![ledger("d1_migrations")];
        for index in 0..D1_WRITE_CATALOG_MAX_OBJECTS {
            rows.push(table(&format!("table_{index}")));
        }
        let over_limit = response(rows);
        assert_eq!(
            classification(&plan, &over_limit, &over_limit),
            D1WriteAuthorityClassification::CatalogObjectLimitExceeded
        );
    }
}
