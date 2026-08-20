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
pub(crate) const EFFECT_ASSERTION_SCHEMA_ADDITIVE_SEED_ROWS_V2: &str =
    "schema_create_objects_additive_seed_rows_v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeedAssertionVersion {
    V1,
    V2,
}

impl SeedAssertionVersion {
    fn proof_version(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    fn allows_null(self) -> bool {
        self == Self::V2
    }
}

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
    Null,
    Text(String),
    Integer(i64),
}

impl SeedLiteral {
    fn canonical_value(&self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Text(value) => Value::String(hex_upper(value.as_bytes())),
            Self::Integer(value) => Value::String(value.to_string()),
        }
    }

    fn canonical_value_bytes(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Text(value) => value.len().saturating_mul(2),
            Self::Integer(value) => signed_decimal_len(*value),
        }
    }

    fn storage_class(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Text(_) => "text",
            Self::Integer(_) => "integer",
        }
    }
}

fn signed_decimal_len(value: i64) -> usize {
    if value == 0 {
        return 1;
    }
    let mut magnitude = value.unsigned_abs();
    let mut digits = usize::from(value.is_negative());
    while magnitude > 0 {
        digits += 1;
        magnitude /= 10;
    }
    digits
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeedInsertEffect {
    pub(crate) assertion_version: SeedAssertionVersion,
    pub(crate) table_name: String,
    pub(crate) columns: Vec<String>,
    pub(crate) rows: Vec<Vec<SeedLiteral>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeedTableState {
    pub(crate) assertion_version: SeedAssertionVersion,
    pub(crate) table_name: String,
    pub(crate) columns: Vec<String>,
    pub(crate) rows: Vec<Vec<SeedLiteral>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeedManifestPlan {
    /// Complete cumulative seed-table state for every manifest prefix,
    /// including prefix zero.
    pub(crate) states: Vec<Vec<SeedTableState>>,
    /// SQLite ASCII-normalized identities of manifest-created STRICT tables.
    pub(crate) strict_table_keys: BTreeSet<String>,
    /// Full-manifest projection registry. A registered table exists in every
    /// state at or after `created_prefix`, with zero rows until `seeded_prefix`.
    pub(crate) registry: Vec<SeedTableRegistration>,
    /// Deterministic first-seen spellings for baseline/pre-existing table
    /// identities referenced by additive effects.
    pub(crate) preexisting_table_spellings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeedTableRegistration {
    pub(crate) state: SeedTableState,
    pub(crate) created_prefix: usize,
    pub(crate) seeded_prefix: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeedContractError {
    pub(crate) capability_state: &'static str,
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

impl SeedContractError {
    fn grammar(assertion_version: SeedAssertionVersion) -> Self {
        Self {
            capability_state: "capability_gap",
            code: "d1.migration_reconciliation_seed_insert_effect_unavailable",
            message: match assertion_version {
                SeedAssertionVersion::V1 => {
                    "the seed-row assertion accepts only plain unqualified INSERT INTO a manifest-created table with explicit canonical columns and bounded TEXT or INTEGER literal VALUES tuples"
                }
                SeedAssertionVersion::V2 => {
                    "the seed-row v2 assertion accepts only plain unqualified INSERT INTO a manifest-created table with explicit canonical columns and bounded NULL, TEXT, or INTEGER literal VALUES tuples"
                }
            },
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
    assertion_version: SeedAssertionVersion,
) -> Result<Option<SeedInsertEffect>, SeedContractError> {
    if !token_is_word(tokens.first(), "insert") {
        return Ok(None);
    }
    if tokens.len() > MAX_SEED_STATEMENT_TOKENS || !token_is_word(tokens.get(1), "into") {
        return Err(SeedContractError::grammar(assertion_version));
    }
    let table_name = canonical_plain_identifier(tokens.get(2))
        .ok_or_else(|| SeedContractError::grammar(assertion_version))?;
    if tokens.get(3) != Some(&SqlToken::Symbol('(')) {
        return Err(SeedContractError::grammar(assertion_version));
    }

    let mut cursor = 4usize;
    let mut columns = Vec::new();
    let mut column_names = BTreeSet::new();
    loop {
        let column = canonical_plain_identifier(tokens.get(cursor))
            .ok_or_else(|| SeedContractError::grammar(assertion_version))?;
        if !column_names.insert(column.to_ascii_lowercase())
            || columns.len() >= MAX_SEED_COLUMNS_PER_TABLE
        {
            return Err(SeedContractError::grammar(assertion_version));
        }
        columns.push(column);
        cursor += 1;
        match tokens.get(cursor) {
            Some(SqlToken::Symbol(',')) => cursor += 1,
            Some(SqlToken::Symbol(')')) => {
                cursor += 1;
                break;
            }
            _ => return Err(SeedContractError::grammar(assertion_version)),
        }
    }
    if columns.is_empty() || !token_is_word(tokens.get(cursor), "values") {
        return Err(SeedContractError::grammar(assertion_version));
    }
    cursor += 1;

    let mut rows = Vec::new();
    let mut literal_bytes_total = 0usize;
    loop {
        if tokens.get(cursor) != Some(&SqlToken::Symbol('('))
            || rows.len() >= MAX_SEED_ROWS_PER_TABLE
        {
            return Err(SeedContractError::grammar(assertion_version));
        }
        cursor += 1;
        let mut row = Vec::with_capacity(columns.len());
        for column_index in 0..columns.len() {
            let (literal, width) = parse_literal(tokens, cursor, assertion_version)?;
            literal_bytes_total = literal_bytes_total
                .checked_add(literal.canonical_value_bytes())
                .filter(|bytes| *bytes <= MAX_SEED_LITERAL_BYTES_TOTAL)
                .ok_or_else(|| SeedContractError::grammar(assertion_version))?;
            row.push(literal);
            cursor += width;
            if column_index + 1 < columns.len() {
                if tokens.get(cursor) != Some(&SqlToken::Symbol(',')) {
                    return Err(SeedContractError::grammar(assertion_version));
                }
                cursor += 1;
            }
        }
        if tokens.get(cursor) != Some(&SqlToken::Symbol(')')) {
            return Err(SeedContractError::grammar(assertion_version));
        }
        cursor += 1;
        rows.push(row);
        match tokens.get(cursor) {
            Some(SqlToken::Symbol(',')) => cursor += 1,
            None => break,
            _ => return Err(SeedContractError::grammar(assertion_version)),
        }
    }
    if rows.is_empty() {
        return Err(SeedContractError::grammar(assertion_version));
    }
    rows.sort();
    if rows.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SeedContractError::contradictory(
            "d1.migration_reconciliation_seed_rows_duplicate",
            "one canonical seed INSERT contains duplicate literal tuples",
        ));
    }
    Ok(Some(SeedInsertEffect {
        assertion_version,
        table_name,
        columns,
        rows,
    }))
}

fn parse_literal(
    tokens: &[SqlToken],
    cursor: usize,
    assertion_version: SeedAssertionVersion,
) -> Result<(SeedLiteral, usize), SeedContractError> {
    match tokens.get(cursor) {
        Some(SqlToken::Word(value))
            if assertion_version.allows_null() && value.eq_ignore_ascii_case("null") =>
        {
            Ok((SeedLiteral::Null, 1))
        }
        Some(SqlToken::StringLiteral(value))
            if value.as_bytes().len() <= MAX_SEED_VALUE_BYTES && !value.contains('\0') =>
        {
            Ok((SeedLiteral::Text(value.clone()), 1))
        }
        Some(SqlToken::Word(value)) => parse_integer(value)
            .map(|value| (SeedLiteral::Integer(value), 1))
            .ok_or_else(|| SeedContractError::grammar(assertion_version)),
        Some(SqlToken::Symbol('-')) => tokens
            .get(cursor + 1)
            .and_then(|token| match token {
                SqlToken::Word(value) => canonical_negative_integer(value),
                _ => None,
            })
            .map(|value| (SeedLiteral::Integer(value), 2))
            .ok_or_else(|| SeedContractError::grammar(assertion_version)),
        _ => Err(SeedContractError::grammar(assertion_version)),
    }
}

fn parse_integer(value: &str) -> Option<i64> {
    canonical_unsigned_integer(value)
}

fn canonical_unsigned_integer(value: &str) -> Option<i64> {
    if !canonical_unsigned_decimal_grammar(value) {
        return None;
    }
    value.parse().ok()
}

fn canonical_negative_integer(magnitude: &str) -> Option<i64> {
    if !canonical_unsigned_decimal_grammar(magnitude) || magnitude == "0" {
        return None;
    }
    let magnitude = magnitude.parse::<u64>().ok()?;
    if magnitude == i64::MAX as u64 + 1 {
        Some(i64::MIN)
    } else {
        i64::try_from(magnitude).ok()?.checked_neg()
    }
}

fn canonical_unsigned_decimal_grammar(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
}

pub(crate) fn sqlite_ascii_identifier_key(value: &str) -> String {
    value.to_ascii_lowercase()
}

pub(crate) fn seed_literal_is_identity_stable_for_declared_type(
    literal: &SeedLiteral,
    declared_type: &str,
    strict_table: bool,
    not_null: bool,
) -> bool {
    if matches!(literal, SeedLiteral::Null) {
        return !not_null;
    }
    let declared_type = declared_type.to_ascii_uppercase();
    if strict_table {
        return matches!(
            (literal, declared_type.as_str()),
            (SeedLiteral::Text(_), "TEXT") | (SeedLiteral::Integer(_), "INT" | "INTEGER")
        );
    }
    let affinity = if declared_type.contains("INT") {
        "integer"
    } else if ["CHAR", "CLOB", "TEXT"]
        .iter()
        .any(|fragment| declared_type.contains(fragment))
    {
        "text"
    } else if declared_type.is_empty() || declared_type.contains("BLOB") {
        "blob"
    } else if ["REAL", "FLOA", "DOUB"]
        .iter()
        .any(|fragment| declared_type.contains(fragment))
    {
        "real"
    } else {
        "numeric"
    };
    matches!(
        (literal, affinity),
        (SeedLiteral::Text(_), "text" | "blob")
            | (SeedLiteral::Integer(_), "integer" | "numeric" | "blob")
    )
}

pub(crate) fn insert_seed_effect(
    cumulative: &mut BTreeMap<String, SeedTableState>,
    effect: SeedInsertEffect,
) -> Result<(), SeedContractError> {
    let authority_key = sqlite_ascii_identifier_key(&effect.table_name);
    if cumulative.len() >= MAX_SEED_TABLES || cumulative.contains_key(&authority_key) {
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
        authority_key,
        SeedTableState {
            assertion_version: effect.assertion_version,
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
    seed_summary_from_canonical_rows(
        state.assertion_version,
        &state.table_name,
        &state.columns,
        canonical_rows,
    )
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
            if state.rows.is_empty() {
                return [
                    format!("NULL AS \"t{index}\""),
                    format!("NULL AS \"v{index}\""),
                ];
            }
            let column = quote_identifier(column);
            let value_projection = match state.assertion_version {
                SeedAssertionVersion::V1 => format!(
                    "CASE typeof({column}) WHEN 'text' THEN hex(CAST({column} AS BLOB)) WHEN 'integer' THEN printf('%lld', {column}) ELSE NULL END AS \"v{index}\""
                ),
                SeedAssertionVersion::V2 => format!(
                    "CASE typeof({column}) WHEN 'null' THEN NULL WHEN 'text' THEN hex(CAST({column} AS BLOB)) WHEN 'integer' THEN printf('%lld', {column}) ELSE NULL END AS \"v{index}\""
                ),
            };
            [
                format!("typeof({column}) AS \"t{index}\""),
                value_projection,
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
            let value = object
                .get(&format!("v{index}"))
                .ok_or_else(seed_row_malformed)?;
            let valid = match storage_class.as_str() {
                "null" => state.assertion_version.allows_null() && value.is_null(),
                "text" => {
                    let Some(value) = value.as_str() else {
                        return Err(seed_row_malformed());
                    };
                    value.len() <= MAX_SEED_VALUE_BYTES * 2
                        && value.len() % 2 == 0
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
                }
                "integer" => value.as_str().is_some_and(canonical_signed_decimal),
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
        state.assertion_version,
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
    assertion_version: SeedAssertionVersion,
    table_name: &str,
    columns: &[String],
    rows: Vec<Vec<Value>>,
) -> D1MigrationSeedTableExpectation {
    let row_count = rows.len();
    let proof = json!({
        "version": assertion_version.proof_version(),
        "table_name": table_name,
        "columns": columns,
        "rows": rows,
    });
    D1MigrationSeedTableExpectation {
        table_name: table_name.to_string(),
        columns: columns.to_vec(),
        row_count,
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
        let parsed = classify_seed_insert(&tokens, SeedAssertionVersion::V1)
            .expect("closed grammar")
            .expect("seed INSERT");
        assert_eq!(parsed.table_name, "publications");
        assert_eq!(parsed.columns, ["publication", "display_name"]);
        assert_eq!(parsed.rows.len(), 2);
    }

    #[test]
    fn parses_the_complete_canonical_signed_integer_range() {
        let minimum = vec![
            SqlToken::Word("INSERT".into()),
            SqlToken::Word("INTO".into()),
            SqlToken::Word("ranges".into()),
            SqlToken::Symbol('('),
            SqlToken::Word("value".into()),
            SqlToken::Symbol(')'),
            SqlToken::Word("VALUES".into()),
            SqlToken::Symbol('('),
            SqlToken::Symbol('-'),
            SqlToken::Word("9223372036854775808".into()),
            SqlToken::Symbol(')'),
        ];
        let parsed = classify_seed_insert(&minimum, SeedAssertionVersion::V1)
            .expect("minimum i64 is canonical")
            .expect("seed INSERT");
        assert_eq!(parsed.rows, vec![vec![SeedLiteral::Integer(i64::MIN)]]);
        assert!(canonical_signed_decimal("-9223372036854775808"));
        assert!(!canonical_signed_decimal("-9223372036854775809"));
        assert_eq!(signed_decimal_len(i64::MIN), 20);
        assert_eq!(signed_decimal_len(i64::MAX), 19);
        assert_eq!(signed_decimal_len(0), 1);
    }

    #[test]
    fn cumulative_seed_authority_rejects_ascii_case_aliases() {
        let effect = |table_name: &str| SeedInsertEffect {
            assertion_version: SeedAssertionVersion::V1,
            table_name: table_name.to_string(),
            columns: vec!["id".into()],
            rows: vec![vec![SeedLiteral::Text("x".into())]],
        };
        let mut cumulative = BTreeMap::new();
        insert_seed_effect(&mut cumulative, effect("Channels")).expect("first target");
        let error = insert_seed_effect(&mut cumulative, effect("CHANNELS"))
            .expect_err("case alias must reuse one SQLite target");
        assert_eq!(error.code, "d1.migration_reconciliation_seed_target_reused");
        assert_eq!(cumulative["channels"].table_name, "Channels");
    }

    #[test]
    fn zero_row_projection_does_not_require_future_seed_columns() {
        let state = SeedTableState {
            assertion_version: SeedAssertionVersion::V1,
            table_name: "channels".into(),
            columns: vec!["future_rank".into()],
            rows: Vec::new(),
        };
        let sql = seed_select_sql(&state);
        assert_eq!(
            sql,
            "SELECT NULL AS \"t0\", NULL AS \"v0\" FROM \"channels\" ORDER BY \"t0\", \"v0\" LIMIT 1"
        );
        assert!(!sql.contains("future_rank"));
    }

    #[test]
    fn seed_literals_require_identity_stable_sqlite_affinity() {
        let text = SeedLiteral::Text("42".into());
        let integer = SeedLiteral::Integer(i64::MIN);

        for declared_type in ["TEXT", "VARCHAR(12)", "CLOB", "", "BLOB"] {
            assert!(seed_literal_is_identity_stable_for_declared_type(
                &text,
                declared_type,
                false,
                false,
            ));
        }
        for declared_type in ["INTEGER", "BIGINT", "BOOLEAN", "NUMERIC", "", "BLOB"] {
            assert!(seed_literal_is_identity_stable_for_declared_type(
                &integer,
                declared_type,
                false,
                false,
            ));
        }
        for declared_type in ["INTEGER", "NUMERIC", "BOOLEAN", "REAL", "DOUBLE"] {
            assert!(!seed_literal_is_identity_stable_for_declared_type(
                &text,
                declared_type,
                false,
                false,
            ));
        }
        for declared_type in ["TEXT", "VARCHAR(12)", "REAL", "DOUBLE"] {
            assert!(!seed_literal_is_identity_stable_for_declared_type(
                &integer,
                declared_type,
                false,
                false,
            ));
        }

        assert!(seed_literal_is_identity_stable_for_declared_type(
            &text, "TEXT", true, false,
        ));
        assert!(seed_literal_is_identity_stable_for_declared_type(
            &integer, "INT", true, false,
        ));
        assert!(seed_literal_is_identity_stable_for_declared_type(
            &integer, "INTEGER", true, false,
        ));
        for (literal, declared_type) in [
            (&text, "BLOB"),
            (&integer, "BLOB"),
            (&text, "ANY"),
            (&integer, "ANY"),
            (&integer, "NUMERIC"),
        ] {
            assert!(!seed_literal_is_identity_stable_for_declared_type(
                literal,
                declared_type,
                true,
                false,
            ));
        }

        let mixed_blob = SeedTableState {
            assertion_version: SeedAssertionVersion::V1,
            table_name: "mixed".into(),
            columns: vec!["value".into()],
            rows: vec![vec![text], vec![integer]],
        };
        assert!(mixed_blob.rows.iter().flatten().all(|literal| {
            seed_literal_is_identity_stable_for_declared_type(literal, "BLOB", false, false)
        }));
    }

    #[test]
    fn rejects_every_non_values_or_conflict_clause_shape() {
        for tokens in [
            words(&["INSERT", "OR", "IGNORE", "INTO", "t"]),
            words(&["INSERT", "INTO", "t", "DEFAULT", "VALUES"]),
            words(&["INSERT", "INTO", "t", "SELECT", "x"]),
            words(&["INSERT", "INTO", "t", "VALUES"]),
        ] {
            assert!(classify_seed_insert(&tokens, SeedAssertionVersion::V1).is_err());
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
            assert!(classify_seed_insert(&tokens, SeedAssertionVersion::V1).is_err());
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
            classify_seed_insert(&duplicate, SeedAssertionVersion::V1)
                .expect_err("duplicate tuple must conflict")
                .code,
            "d1.migration_reconciliation_seed_rows_duplicate"
        );
    }

    #[test]
    fn v2_accepts_exactly_bounded_canonical_null_literals_without_broadening_v1() {
        let mut tokens = vec![
            SqlToken::Word("INSERT".into()),
            SqlToken::Word("INTO".into()),
            SqlToken::Word("bootstrap_state".into()),
            SqlToken::Symbol('('),
        ];
        for index in 0..7 {
            if index > 0 {
                tokens.push(SqlToken::Symbol(','));
            }
            tokens.push(SqlToken::Word(format!("value_{index}")));
        }
        tokens.extend([
            SqlToken::Symbol(')'),
            SqlToken::Word("VALUES".into()),
            SqlToken::Symbol('('),
        ]);
        for index in 0..7 {
            if index > 0 {
                tokens.push(SqlToken::Symbol(','));
            }
            tokens.push(SqlToken::Word("NULL".into()));
        }
        tokens.push(SqlToken::Symbol(')'));

        let v1 = classify_seed_insert(&tokens, SeedAssertionVersion::V1)
            .expect_err("v1 must retain its TEXT/INTEGER-only grammar");
        assert_eq!(
            v1.code,
            "d1.migration_reconciliation_seed_insert_effect_unavailable"
        );
        let v2 = classify_seed_insert(&tokens, SeedAssertionVersion::V2)
            .expect("v2 grammar")
            .expect("seed INSERT");
        assert_eq!(v2.assertion_version, SeedAssertionVersion::V2);
        assert_eq!(v2.rows, vec![vec![SeedLiteral::Null; 7]]);
    }

    #[test]
    fn v2_null_hash_and_provider_normalization_are_exact_and_type_sensitive() {
        let state = SeedTableState {
            assertion_version: SeedAssertionVersion::V2,
            table_name: "bootstrap_state".into(),
            columns: vec!["value".into()],
            rows: vec![vec![SeedLiteral::Null]],
        };
        let expected = seed_table_summary(&state);
        let observed = observed_seed_summary(&state, &[json!({"t0": "null", "v0": null})])
            .expect("canonical NULL evidence");
        assert_eq!(observed, expected);
        assert!(seed_select_sql(&state).contains("WHEN 'null' THEN NULL"));

        for malformed in [
            json!({"t0": "null", "v0": ""}),
            json!({"t0": "null", "v0": "NULL"}),
            json!({"t0": "text", "v0": null}),
            json!({"t0": "integer", "v0": null}),
        ] {
            assert_eq!(
                observed_seed_summary(&state, &[malformed])
                    .expect_err("contradictory NULL evidence must fail closed")
                    .code,
                "d1.migration_reconciliation_seed_row_malformed"
            );
        }

        let v1_state = SeedTableState {
            assertion_version: SeedAssertionVersion::V1,
            ..state.clone()
        };
        assert_ne!(
            seed_table_summary(&v1_state).rows_sha256,
            expected.rows_sha256,
            "the v2 row-set proof identity must not alias v1"
        );
        assert!(!seed_select_sql(&v1_state).contains("WHEN 'null' THEN NULL"));
    }

    #[test]
    fn null_affinity_requires_a_nullable_reviewed_column() {
        let null = SeedLiteral::Null;
        for strict in [false, true] {
            for declared_type in ["", "TEXT", "INTEGER", "REAL", "BLOB", "ANY"] {
                assert!(seed_literal_is_identity_stable_for_declared_type(
                    &null,
                    declared_type,
                    strict,
                    false,
                ));
                assert!(!seed_literal_is_identity_stable_for_declared_type(
                    &null,
                    declared_type,
                    strict,
                    true,
                ));
            }
        }
    }

    #[test]
    fn observed_summary_is_type_sensitive_and_aggregate_safe() {
        let state = SeedTableState {
            assertion_version: SeedAssertionVersion::V1,
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
            assertion_version: SeedAssertionVersion::V1,
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
            assertion_version: SeedAssertionVersion::V1,
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
