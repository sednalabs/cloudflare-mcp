//! Closed canonical seed-row effects for retained D1 migration reconciliation.
//!
//! This module owns the new assertion's deliberately small top-level INSERT
//! grammar, cumulative row-set model, aggregate-safe expectation summaries,
//! and exact observed-row normalization. Provider reads, schema proof, custody,
//! and terminal receipts remain owned by the existing reconciliation pipeline.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::d1_migration_reconciliation::SqlToken;
use crate::tools::sha256_bytes_hex;

pub(crate) const EFFECT_ASSERTION_SCHEMA_ADDITIVE_SEED_ROWS_V1: &str =
    "schema_create_objects_additive_seed_rows_v1";

pub(crate) const MAX_SEED_TABLES: usize = 16;
pub(crate) const MAX_SEED_COLUMNS_PER_TABLE: usize = 16;
pub(crate) const MAX_SEED_ROWS_PER_TABLE: usize = 256;
const MAX_SEED_ROWS_TOTAL: usize = 1_024;
const MAX_SEED_VALUE_BYTES: usize = 1_024;
const MAX_SEED_LITERAL_BYTES_TOTAL: usize = 64 * 1024;
const MAX_SEED_STATEMENT_TOKENS: usize = 4_096;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct D1MigrationSeedTableExpectation {
    pub table_name: String,
    pub columns: Vec<String>,
    pub row_count: usize,
    pub rows_sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "storage_class", content = "value", rename_all = "snake_case")]
pub(crate) enum SeedLiteral {
    Text(String),
    Integer(i64),
}

impl SeedLiteral {
    fn canonical_value(&self) -> String {
        match self {
            Self::Text(value) => hex_upper(value.as_bytes()),
            Self::Integer(value) => value.to_string(),
        }
    }

    fn storage_class(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::Integer(_) => "integer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeedInsertEffect {
    pub(crate) table_name: String,
    pub(crate) columns: Vec<String>,
    pub(crate) rows: Vec<Vec<SeedLiteral>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeedTableState {
    pub(crate) table_name: String,
    pub(crate) columns: Vec<String>,
    pub(crate) rows: Vec<Vec<SeedLiteral>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeedManifestPlan {
    /// Complete cumulative seed-table state for every manifest prefix,
    /// including prefix zero.
    pub(crate) states: Vec<Vec<SeedTableState>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeedContractError {
    pub(crate) capability_state: &'static str,
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

impl SeedContractError {
    fn grammar() -> Self {
        Self {
            capability_state: "capability_gap",
            code: "d1.migration_reconciliation_seed_insert_effect_unavailable",
            message: "the seed-row assertion accepts only plain unqualified INSERT INTO a manifest-created table with explicit canonical columns and bounded TEXT or INTEGER literal VALUES tuples",
        }
    }

    pub(crate) fn contradictory(code: &'static str, message: &'static str) -> Self {
        Self {
            capability_state: "contradictory",
            code,
            message,
        }
    }
}

pub(crate) fn classify_seed_insert(
    tokens: &[SqlToken],
) -> Result<Option<SeedInsertEffect>, SeedContractError> {
    if !token_is_word(tokens.first(), "insert") {
        return Ok(None);
    }
    if tokens.len() > MAX_SEED_STATEMENT_TOKENS || !token_is_word(tokens.get(1), "into") {
        return Err(SeedContractError::grammar());
    }
    let table_name =
        canonical_plain_identifier(tokens.get(2)).ok_or_else(SeedContractError::grammar)?;
    if tokens.get(3) != Some(&SqlToken::Symbol('(')) {
        return Err(SeedContractError::grammar());
    }

    let mut cursor = 4usize;
    let mut columns = Vec::new();
    let mut column_names = BTreeSet::new();
    loop {
        let column = canonical_plain_identifier(tokens.get(cursor))
            .ok_or_else(SeedContractError::grammar)?;
        if !column_names.insert(column.to_ascii_lowercase())
            || columns.len() >= MAX_SEED_COLUMNS_PER_TABLE
        {
            return Err(SeedContractError::grammar());
        }
        columns.push(column);
        cursor += 1;
        match tokens.get(cursor) {
            Some(SqlToken::Symbol(',')) => cursor += 1,
            Some(SqlToken::Symbol(')')) => {
                cursor += 1;
                break;
            }
            _ => return Err(SeedContractError::grammar()),
        }
    }
    if columns.is_empty() || !token_is_word(tokens.get(cursor), "values") {
        return Err(SeedContractError::grammar());
    }
    cursor += 1;

    let mut rows = Vec::new();
    let mut literal_bytes_total = 0usize;
    loop {
        if tokens.get(cursor) != Some(&SqlToken::Symbol('('))
            || rows.len() >= MAX_SEED_ROWS_PER_TABLE
        {
            return Err(SeedContractError::grammar());
        }
        cursor += 1;
        let mut row = Vec::with_capacity(columns.len());
        for column_index in 0..columns.len() {
            let (literal, width) = parse_literal(tokens, cursor)?;
            literal_bytes_total = literal_bytes_total
                .checked_add(literal.canonical_value().len())
                .filter(|bytes| *bytes <= MAX_SEED_LITERAL_BYTES_TOTAL)
                .ok_or_else(SeedContractError::grammar)?;
            row.push(literal);
            cursor += width;
            if column_index + 1 < columns.len() {
                if tokens.get(cursor) != Some(&SqlToken::Symbol(',')) {
                    return Err(SeedContractError::grammar());
                }
                cursor += 1;
            }
        }
        if tokens.get(cursor) != Some(&SqlToken::Symbol(')')) {
            return Err(SeedContractError::grammar());
        }
        cursor += 1;
        rows.push(row);
        match tokens.get(cursor) {
            Some(SqlToken::Symbol(',')) => cursor += 1,
            None => break,
            _ => return Err(SeedContractError::grammar()),
        }
    }
    if rows.is_empty() {
        return Err(SeedContractError::grammar());
    }
    rows.sort();
    if rows.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SeedContractError::contradictory(
            "d1.migration_reconciliation_seed_rows_duplicate",
            "one canonical seed INSERT contains duplicate literal tuples",
        ));
    }
    Ok(Some(SeedInsertEffect {
        table_name,
        columns,
        rows,
    }))
}

fn parse_literal(
    tokens: &[SqlToken],
    cursor: usize,
) -> Result<(SeedLiteral, usize), SeedContractError> {
    match tokens.get(cursor) {
        Some(SqlToken::StringLiteral(value))
            if value.as_bytes().len() <= MAX_SEED_VALUE_BYTES && !value.contains('\0') =>
        {
            Ok((SeedLiteral::Text(value.clone()), 1))
        }
        Some(SqlToken::Word(value)) => parse_integer(value)
            .map(|value| (SeedLiteral::Integer(value), 1))
            .ok_or_else(SeedContractError::grammar),
        Some(SqlToken::Symbol('-')) => tokens
            .get(cursor + 1)
            .and_then(|token| match token {
                SqlToken::Word(value) => canonical_unsigned_integer(value),
                _ => None,
            })
            .and_then(|value| value.checked_neg())
            .filter(|value| *value != 0)
            .map(|value| (SeedLiteral::Integer(value), 2))
            .ok_or_else(SeedContractError::grammar),
        _ => Err(SeedContractError::grammar()),
    }
}

fn parse_integer(value: &str) -> Option<i64> {
    canonical_unsigned_integer(value)
}

fn canonical_unsigned_integer(value: &str) -> Option<i64> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse().ok()
}

pub(crate) fn insert_seed_effect(
    cumulative: &mut BTreeMap<String, SeedTableState>,
    effect: SeedInsertEffect,
) -> Result<(), SeedContractError> {
    if cumulative.len() >= MAX_SEED_TABLES || cumulative.contains_key(&effect.table_name) {
        return Err(SeedContractError::contradictory(
            "d1.migration_reconciliation_seed_target_reused",
            "each manifest-created seed table may have exactly one canonical top-level seed INSERT",
        ));
    }
    let rows_total = cumulative
        .values()
        .map(|state| state.rows.len())
        .sum::<usize>()
        .checked_add(effect.rows.len())
        .filter(|rows| *rows <= MAX_SEED_ROWS_TOTAL)
        .ok_or_else(|| {
            SeedContractError::contradictory(
                "d1.migration_reconciliation_seed_rows_unbounded",
                "the cumulative seed-row set exceeds the closed assertion bound",
            )
        })?;
    let _ = rows_total;
    cumulative.insert(
        effect.table_name.clone(),
        SeedTableState {
            table_name: effect.table_name,
            columns: effect.columns,
            rows: effect.rows,
        },
    );
    Ok(())
}

pub(crate) fn state_summaries(states: &[SeedTableState]) -> Vec<D1MigrationSeedTableExpectation> {
    states.iter().map(seed_table_summary).collect()
}

pub(crate) fn seed_table_summary(state: &SeedTableState) -> D1MigrationSeedTableExpectation {
    let mut canonical_rows = state
        .rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|literal| {
                    json!({
                        "storage_class": literal.storage_class(),
                        "value": literal.canonical_value(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    sort_canonical_rows(&mut canonical_rows);
    seed_summary_from_canonical_rows(&state.table_name, &state.columns, canonical_rows)
}

pub(crate) fn seed_data_fields(column_count: usize) -> Vec<String> {
    (0..column_count)
        .flat_map(|index| [format!("t{index}"), format!("v{index}")])
        .collect()
}

pub(crate) fn seed_select_sql(state: &SeedTableState) -> String {
    let projections = state
        .columns
        .iter()
        .enumerate()
        .flat_map(|(index, column)| {
            let column = quote_identifier(column);
            [
                format!("typeof({column}) AS \"t{index}\""),
                format!(
                    "CASE typeof({column}) WHEN 'text' THEN hex(CAST({column} AS BLOB)) WHEN 'integer' THEN printf('%lld', {column}) ELSE NULL END AS \"v{index}\""
                ),
            ]
        })
        .collect::<Vec<_>>();
    let order = (0..state.columns.len())
        .flat_map(|index| [format!("\"t{index}\""), format!("\"v{index}\"")])
        .collect::<Vec<_>>();
    format!(
        "SELECT {} FROM {} ORDER BY {} LIMIT {}",
        projections.join(", "),
        quote_identifier(&state.table_name),
        order.join(", "),
        state.rows.len() + 1,
    )
}

pub(crate) fn observed_seed_summary(
    state: &SeedTableState,
    rows: &[Value],
) -> Result<D1MigrationSeedTableExpectation, SeedContractError> {
    if rows.len() > state.rows.len() {
        return Err(SeedContractError::contradictory(
            "d1.migration_reconciliation_seed_rows_extra",
            "seed-row readback exceeded the complete reviewed row-set bound",
        ));
    }
    let expected_fields = seed_data_fields(state.columns.len());
    let expected_keys = expected_fields
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut canonical_rows = Vec::with_capacity(rows.len());
    for row in rows {
        let object = row.as_object().ok_or_else(seed_row_malformed)?;
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_keys {
            return Err(seed_row_malformed());
        }
        let mut canonical = Vec::with_capacity(state.columns.len());
        for index in 0..state.columns.len() {
            let storage_class = exact_string(object, &format!("t{index}"))?;
            let value = exact_string(object, &format!("v{index}"))?;
            let valid = match storage_class.as_str() {
                "text" => {
                    value.len() <= MAX_SEED_VALUE_BYTES * 2
                        && value.len() % 2 == 0
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
                }
                "integer" => canonical_signed_decimal(&value),
                _ => false,
            };
            if !valid {
                return Err(seed_row_malformed());
            }
            canonical.push(json!({"storage_class": storage_class, "value": value}));
        }
        canonical_rows.push(canonical);
    }
    sort_canonical_rows(&mut canonical_rows);
    Ok(seed_summary_from_canonical_rows(
        &state.table_name,
        &state.columns,
        canonical_rows,
    ))
}

fn sort_canonical_rows(rows: &mut [Vec<Value>]) {
    rows.sort_by(|left, right| {
        serde_json::to_vec(left)
            .expect("seed row serialization")
            .cmp(&serde_json::to_vec(right).expect("seed row serialization"))
    });
}

fn seed_summary_from_canonical_rows(
    table_name: &str,
    columns: &[String],
    rows: Vec<Vec<Value>>,
) -> D1MigrationSeedTableExpectation {
    let proof = json!({
        "version": 1,
        "table_name": table_name,
        "columns": columns,
        "rows": rows,
    });
    D1MigrationSeedTableExpectation {
        table_name: table_name.to_string(),
        columns: columns.to_vec(),
        row_count: proof["rows"].as_array().map_or(0, Vec::len),
        rows_sha256: sha256_bytes_hex(
            &serde_json::to_vec(&proof).expect("canonical seed-row proof serialization"),
        ),
    }
}

fn exact_string(object: &Map<String, Value>, key: &str) -> Result<String, SeedContractError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(seed_row_malformed)
}

fn seed_row_malformed() -> SeedContractError {
    SeedContractError::contradictory(
        "d1.migration_reconciliation_seed_row_malformed",
        "seed-row provider evidence had a missing field, unexpected field, unsupported storage class, or noncanonical value",
    )
}

fn canonical_signed_decimal(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix('-') {
        return !rest.is_empty()
            && rest != "0"
            && !rest.starts_with('0')
            && rest.bytes().all(|byte| byte.is_ascii_digit())
            && value.parse::<i64>().is_ok();
    }
    canonical_unsigned_integer(value).is_some()
}

fn canonical_plain_identifier(token: Option<&SqlToken>) -> Option<String> {
    match token? {
        SqlToken::Word(value) if valid_identifier(value) => Some(value.clone()),
        _ => None,
    }
}

fn valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 128
        && matches!(bytes.next(), Some(byte) if byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn token_is_word(token: Option<&SqlToken>, value: &str) -> bool {
    matches!(token, Some(SqlToken::Word(word)) if word.eq_ignore_ascii_case(value))
}

fn quote_identifier(value: &str) -> String {
    format!("\"{value}\"")
}

fn hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(values: &[&str]) -> Vec<SqlToken> {
        values
            .iter()
            .map(|value| SqlToken::Word((*value).to_string()))
            .collect()
    }

    #[test]
    fn parses_closed_multirow_literal_insert() {
        let tokens = vec![
            SqlToken::Word("INSERT".into()),
            SqlToken::Word("INTO".into()),
            SqlToken::Word("publications".into()),
            SqlToken::Symbol('('),
            SqlToken::Word("publication".into()),
            SqlToken::Symbol(','),
            SqlToken::Word("display_name".into()),
            SqlToken::Symbol(')'),
            SqlToken::Word("VALUES".into()),
            SqlToken::Symbol('('),
            SqlToken::StringLiteral("alpha".into()),
            SqlToken::Symbol(','),
            SqlToken::StringLiteral("Alpha".into()),
            SqlToken::Symbol(')'),
            SqlToken::Symbol(','),
            SqlToken::Symbol('('),
            SqlToken::StringLiteral("beta".into()),
            SqlToken::Symbol(','),
            SqlToken::StringLiteral("Beta".into()),
            SqlToken::Symbol(')'),
        ];
        let parsed = classify_seed_insert(&tokens)
            .expect("closed grammar")
            .expect("seed INSERT");
        assert_eq!(parsed.table_name, "publications");
        assert_eq!(parsed.columns, ["publication", "display_name"]);
        assert_eq!(parsed.rows.len(), 2);
    }

    #[test]
    fn rejects_every_non_values_or_conflict_clause_shape() {
        for tokens in [
            words(&["INSERT", "OR", "IGNORE", "INTO", "t"]),
            words(&["INSERT", "INTO", "t", "DEFAULT", "VALUES"]),
            words(&["INSERT", "INTO", "t", "SELECT", "x"]),
            words(&["INSERT", "INTO", "t", "VALUES"]),
        ] {
            assert!(classify_seed_insert(&tokens).is_err());
        }
    }

    #[test]
    fn rejects_expression_null_real_qualified_and_duplicate_seed_shapes() {
        for tokens in [
            vec![
                SqlToken::Word("INSERT".into()),
                SqlToken::Word("INTO".into()),
                SqlToken::Word("main".into()),
                SqlToken::Symbol('.'),
                SqlToken::Word("items".into()),
            ],
            vec![
                SqlToken::Word("INSERT".into()),
                SqlToken::Word("INTO".into()),
                SqlToken::Word("items".into()),
                SqlToken::Symbol('('),
                SqlToken::Word("id".into()),
                SqlToken::Symbol(','),
                SqlToken::Word("ID".into()),
                SqlToken::Symbol(')'),
                SqlToken::Word("VALUES".into()),
                SqlToken::Symbol('('),
                SqlToken::StringLiteral("x".into()),
                SqlToken::Symbol(','),
                SqlToken::StringLiteral("y".into()),
                SqlToken::Symbol(')'),
            ],
            vec![
                SqlToken::Word("INSERT".into()),
                SqlToken::Word("INTO".into()),
                SqlToken::Word("items".into()),
                SqlToken::Symbol('('),
                SqlToken::Word("id".into()),
                SqlToken::Symbol(')'),
                SqlToken::Word("VALUES".into()),
                SqlToken::Symbol('('),
                SqlToken::Word("NULL".into()),
                SqlToken::Symbol(')'),
            ],
            vec![
                SqlToken::Word("INSERT".into()),
                SqlToken::Word("INTO".into()),
                SqlToken::Word("items".into()),
                SqlToken::Symbol('('),
                SqlToken::Word("id".into()),
                SqlToken::Symbol(')'),
                SqlToken::Word("VALUES".into()),
                SqlToken::Symbol('('),
                SqlToken::Word("1.5".into()),
                SqlToken::Symbol(')'),
            ],
            vec![
                SqlToken::Word("INSERT".into()),
                SqlToken::Word("INTO".into()),
                SqlToken::Word("items".into()),
                SqlToken::Symbol('('),
                SqlToken::Word("id".into()),
                SqlToken::Symbol(')'),
                SqlToken::Word("VALUES".into()),
                SqlToken::Symbol('('),
                SqlToken::Word("lower".into()),
                SqlToken::Symbol('('),
                SqlToken::StringLiteral("x".into()),
                SqlToken::Symbol(')'),
                SqlToken::Symbol(')'),
            ],
        ] {
            assert!(classify_seed_insert(&tokens).is_err());
        }

        let duplicate = vec![
            SqlToken::Word("INSERT".into()),
            SqlToken::Word("INTO".into()),
            SqlToken::Word("items".into()),
            SqlToken::Symbol('('),
            SqlToken::Word("id".into()),
            SqlToken::Symbol(')'),
            SqlToken::Word("VALUES".into()),
            SqlToken::Symbol('('),
            SqlToken::StringLiteral("x".into()),
            SqlToken::Symbol(')'),
            SqlToken::Symbol(','),
            SqlToken::Symbol('('),
            SqlToken::StringLiteral("x".into()),
            SqlToken::Symbol(')'),
        ];
        assert_eq!(
            classify_seed_insert(&duplicate)
                .expect_err("duplicate tuple must conflict")
                .code,
            "d1.migration_reconciliation_seed_rows_duplicate"
        );
    }

    #[test]
    fn observed_summary_is_type_sensitive_and_aggregate_safe() {
        let state = SeedTableState {
            table_name: "channels".into(),
            columns: vec!["id".into()],
            rows: vec![vec![SeedLiteral::Text("1".into())]],
        };
        let expected = seed_table_summary(&state);
        let observed = observed_seed_summary(&state, &[json!({"t0": "text", "v0": "31"})])
            .expect("exact text row");
        assert_eq!(observed, expected);
        let wrong_type = observed_seed_summary(&state, &[json!({"t0": "integer", "v0": "1"})])
            .expect("canonical but different type");
        assert_ne!(wrong_type.rows_sha256, expected.rows_sha256);
        assert!(!serde_json::to_string(&observed).unwrap().contains("31"));
    }

    #[test]
    fn observed_summary_rejects_extra_and_malformed_rows_and_distinguishes_absence() {
        let state = SeedTableState {
            table_name: "channels".into(),
            columns: vec!["id".into()],
            rows: vec![vec![SeedLiteral::Text("a".into())]],
        };
        assert_eq!(
            observed_seed_summary(
                &state,
                &[
                    json!({"t0": "text", "v0": "61"}),
                    json!({"t0": "text", "v0": "62"}),
                ],
            )
            .expect_err("extra row must conflict")
            .code,
            "d1.migration_reconciliation_seed_rows_extra"
        );
        for rows in [
            vec![json!({"t0": "blob", "v0": "61"})],
            vec![json!({"t0": "text", "v0": "6a"})],
            vec![json!({"t0": "text", "v0": "61", "extra": 1})],
            vec![json!({"t0": "integer", "v0": "01"})],
        ] {
            assert_eq!(
                observed_seed_summary(&state, &rows)
                    .expect_err("malformed row must conflict")
                    .code,
                "d1.migration_reconciliation_seed_row_malformed"
            );
        }
        let absent = observed_seed_summary(&state, &[]).expect("bounded empty observation");
        assert_ne!(absent, seed_table_summary(&state));
        assert_eq!(absent.row_count, 0);
    }

    #[test]
    fn expected_and_observed_mixed_types_use_one_canonical_sort_order() {
        let state = SeedTableState {
            table_name: "mixed".into(),
            columns: vec!["value".into()],
            rows: vec![
                vec![SeedLiteral::Text("2".into())],
                vec![SeedLiteral::Integer(1)],
            ],
        };
        let observed = observed_seed_summary(
            &state,
            &[
                json!({"t0": "integer", "v0": "1"}),
                json!({"t0": "text", "v0": "32"}),
            ],
        )
        .expect("mixed canonical rows");
        assert_eq!(observed, seed_table_summary(&state));
    }
}
