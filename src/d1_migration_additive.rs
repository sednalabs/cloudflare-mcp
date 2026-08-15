//! Closed additive-schema effects for retained D1 migration reconciliation.
//!
//! This module owns only the new assertion's ALTER/PRAGMA grammar and the
//! transition proof over already validated prefix expectations. Shared SQL
//! tokenization, CREATE classification, provider reads, custody, and terminal
//! receipts remain owned by the existing reconciliation pipeline.

use std::collections::{BTreeMap, BTreeSet};

use crate::d1_migration_reconciliation::{
    D1MigrationColumnExpectation, D1MigrationStateExpectation, SqlToken,
};

pub(crate) const EFFECT_ASSERTION_SCHEMA_ADDITIVE_V1: &str = "schema_create_objects_additive_v1";

const MAX_CHECK_TOKENS: usize = 96;
const MAX_CHECK_DEPTH: usize = 6;
const MAX_CHECK_IN_VALUES: usize = 16;
const MAX_CHECK_LITERAL_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddColumnEffect {
    pub(crate) table_name: String,
    pub(crate) column: D1MigrationColumnExpectation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdditiveStatement {
    AddColumn(AddColumnEffect),
    ForeignKeysOn,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AdditivePrefixPlan {
    pub(crate) created_objects: BTreeSet<(String, String)>,
    pub(crate) addition: Option<AddColumnEffect>,
    pub(crate) foreign_keys_on: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdditiveManifestPlan {
    pub(crate) prefixes: Vec<AdditivePrefixPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdditiveContractError {
    pub(crate) capability_state: &'static str,
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

impl AdditiveContractError {
    fn alter_grammar() -> Self {
        Self {
            capability_state: "capability_gap",
            code: "d1.migration_reconciliation_add_column_effect_unavailable",
            message: "the additive assertion accepts only one canonical unqualified ALTER TABLE parent ADD [COLUMN] column with one bounded column definition",
        }
    }

    fn pragma_grammar() -> Self {
        Self {
            capability_state: "capability_gap",
            code: "d1.migration_reconciliation_pragma_effect_unavailable",
            message: "the additive assertion accepts only semantic PRAGMA foreign_keys = ON as non-persistent manifest intent",
        }
    }

    pub(crate) fn transition(code: &'static str, message: &'static str) -> Self {
        Self {
            capability_state: "contradictory",
            code,
            message,
        }
    }
}

pub(crate) fn classify_additive_statement(
    tokens: &[SqlToken],
) -> Result<Option<AdditiveStatement>, AdditiveContractError> {
    if token_is_word(tokens.first(), "alter") {
        return parse_add_column(tokens).map(|effect| Some(AdditiveStatement::AddColumn(effect)));
    }
    if token_is_word(tokens.first(), "pragma") {
        if tokens.len() == 4
            && word_identifier(tokens.get(1))
                .is_some_and(|name| name.eq_ignore_ascii_case("foreign_keys"))
            && tokens.get(2) == Some(&SqlToken::Symbol('='))
            && token_is_word(tokens.get(3), "on")
        {
            return Ok(Some(AdditiveStatement::ForeignKeysOn));
        }
        return Err(AdditiveContractError::pragma_grammar());
    }
    Ok(None)
}

fn parse_add_column(tokens: &[SqlToken]) -> Result<AddColumnEffect, AdditiveContractError> {
    if !token_is_word(tokens.get(1), "table") {
        return Err(AdditiveContractError::alter_grammar());
    }
    let table_name = canonical_unquoted_identifier(tokens.get(2))
        .ok_or_else(AdditiveContractError::alter_grammar)?;
    if !token_is_word(tokens.get(3), "add") {
        return Err(AdditiveContractError::alter_grammar());
    }
    let mut cursor = 4;
    if token_is_word(tokens.get(cursor), "column") {
        cursor += 1;
    }
    let column_name = canonical_unquoted_identifier(tokens.get(cursor))
        .ok_or_else(AdditiveContractError::alter_grammar)?;
    cursor += 1;
    let declared_type_token = match tokens.get(cursor) {
        Some(SqlToken::Word(value)) if canonical_type_word(value) => value,
        _ => return Err(AdditiveContractError::alter_grammar()),
    };
    let declared_type = canonical_declared_type(declared_type_token);
    cursor += 1;

    let mut not_null = false;
    if token_is_word(tokens.get(cursor), "not") && token_is_word(tokens.get(cursor + 1), "null") {
        not_null = true;
        cursor += 2;
    }

    let mut default_value = None;
    if token_is_word(tokens.get(cursor), "default") {
        let (value, width) =
            parse_default(tokens, cursor + 1).ok_or_else(AdditiveContractError::alter_grammar)?;
        default_value = Some(value);
        cursor += width + 1;
    }
    if token_is_word(tokens.get(cursor), "check") {
        cursor = parse_check_constraint(tokens, cursor + 1, &column_name)
            .ok_or_else(AdditiveContractError::alter_grammar)?;
    }
    if cursor != tokens.len()
        || (not_null
            && default_value
                .as_deref()
                .is_some_and(|value| value == "NULL"))
    {
        return Err(AdditiveContractError::alter_grammar());
    }

    Ok(AddColumnEffect {
        table_name,
        column: D1MigrationColumnExpectation {
            cid: -1,
            name: column_name,
            declared_type,
            not_null,
            default_value,
            primary_key_position: 0,
            hidden: 0,
        },
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CheckValueKind {
    Column,
    ColumnDerived,
    Literal,
}

struct CheckExpressionParser<'a> {
    tokens: &'a [SqlToken],
    cursor: usize,
    column_name: &'a str,
}

fn parse_check_constraint(tokens: &[SqlToken], cursor: usize, column_name: &str) -> Option<usize> {
    let remaining = tokens.get(cursor..)?;
    if remaining.is_empty() || remaining.len() > MAX_CHECK_TOKENS {
        return None;
    }
    let mut parser = CheckExpressionParser {
        tokens,
        cursor,
        column_name,
    };
    parser.consume_symbol('(')?;
    parser.parse_or_expression(1)?;
    parser.consume_symbol(')')?;
    Some(parser.cursor)
}

impl CheckExpressionParser<'_> {
    fn parse_or_expression(&mut self, depth: usize) -> Option<()> {
        self.ensure_depth(depth)?;
        self.parse_and_expression(depth)?;
        while self.consume_word("or").is_some() {
            self.parse_and_expression(depth)?;
        }
        Some(())
    }

    fn parse_and_expression(&mut self, depth: usize) -> Option<()> {
        self.parse_predicate(depth)?;
        while self.consume_word("and").is_some() {
            self.parse_predicate(depth)?;
        }
        Some(())
    }

    fn parse_predicate(&mut self, depth: usize) -> Option<()> {
        if self.consume_symbol('(').is_some() {
            self.parse_or_expression(depth.checked_add(1)?)?;
            self.consume_symbol(')')?;
            return Some(());
        }

        let left = self.parse_value()?;
        if self.consume_word("is").is_some() {
            if left != CheckValueKind::Column {
                return None;
            }
            self.consume_word("null")?;
            return Some(());
        }
        if self.consume_symbol('=').is_some() {
            if !matches!(left, CheckValueKind::Column | CheckValueKind::ColumnDerived)
                || self.parse_value()? != CheckValueKind::Literal
            {
                return None;
            }
            return Some(());
        }
        if self.consume_word("in").is_some() {
            if left != CheckValueKind::Column {
                return None;
            }
            self.consume_symbol('(')?;
            let mut values = 0usize;
            loop {
                if self.parse_value()? != CheckValueKind::Literal {
                    return None;
                }
                values = values.checked_add(1)?;
                if values > MAX_CHECK_IN_VALUES {
                    return None;
                }
                if self.consume_symbol(',').is_none() {
                    break;
                }
            }
            self.consume_symbol(')')?;
            return Some(());
        }
        None
    }

    fn parse_value(&mut self) -> Option<CheckValueKind> {
        match self.tokens.get(self.cursor)? {
            SqlToken::Word(value)
                if value.eq_ignore_ascii_case("length")
                    && self.tokens.get(self.cursor + 1) == Some(&SqlToken::Symbol('(')) =>
            {
                self.cursor += 2;
                self.consume_column()?;
                self.consume_symbol(')')?;
                Some(CheckValueKind::ColumnDerived)
            }
            SqlToken::Word(value)
                if value.eq_ignore_ascii_case("substr")
                    && self.tokens.get(self.cursor + 1) == Some(&SqlToken::Symbol('(')) =>
            {
                self.cursor += 2;
                self.consume_column()?;
                self.consume_symbol(',')?;
                self.consume_positive_integer()?;
                self.consume_symbol(',')?;
                self.consume_positive_integer()?;
                self.consume_symbol(')')?;
                Some(CheckValueKind::ColumnDerived)
            }
            SqlToken::Word(value) if value.eq_ignore_ascii_case(self.column_name) => {
                self.cursor += 1;
                Some(CheckValueKind::Column)
            }
            SqlToken::Word(value)
                if value.len() <= 10 && value.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                self.cursor += 1;
                Some(CheckValueKind::Literal)
            }
            SqlToken::Symbol('-' | '+') => {
                let Some(SqlToken::Word(value)) = self.tokens.get(self.cursor + 1) else {
                    return None;
                };
                if value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                self.cursor += 2;
                Some(CheckValueKind::Literal)
            }
            SqlToken::StringLiteral(value) if value.len() <= MAX_CHECK_LITERAL_BYTES => {
                self.cursor += 1;
                Some(CheckValueKind::Literal)
            }
            SqlToken::Word(_)
            | SqlToken::Identifier(_)
            | SqlToken::StringLiteral(_)
            | SqlToken::Symbol(_) => None,
        }
    }

    fn consume_column(&mut self) -> Option<()> {
        match self.tokens.get(self.cursor) {
            Some(SqlToken::Word(value)) if value.eq_ignore_ascii_case(self.column_name) => {
                self.cursor += 1;
                Some(())
            }
            _ => None,
        }
    }

    fn consume_positive_integer(&mut self) -> Option<()> {
        match self.tokens.get(self.cursor) {
            Some(SqlToken::Word(value))
                if value.len() <= 10
                    && value.bytes().all(|byte| byte.is_ascii_digit())
                    && value.bytes().any(|byte| byte != b'0') =>
            {
                self.cursor += 1;
                Some(())
            }
            _ => None,
        }
    }

    fn consume_word(&mut self, expected: &str) -> Option<()> {
        if token_is_word(self.tokens.get(self.cursor), expected) {
            self.cursor += 1;
            Some(())
        } else {
            None
        }
    }

    fn consume_symbol(&mut self, expected: char) -> Option<()> {
        if self.tokens.get(self.cursor) == Some(&SqlToken::Symbol(expected)) {
            self.cursor += 1;
            Some(())
        } else {
            None
        }
    }

    fn ensure_depth(&self, depth: usize) -> Option<()> {
        (depth <= MAX_CHECK_DEPTH).then_some(())
    }
}

fn parse_default(tokens: &[SqlToken], cursor: usize) -> Option<(String, usize)> {
    match tokens.get(cursor)? {
        SqlToken::Word(value) if value.eq_ignore_ascii_case("null") => {
            Some(("NULL".to_string(), 1))
        }
        SqlToken::Word(value) if value.bytes().all(|byte| byte.is_ascii_digit()) => {
            Some((value.clone(), 1))
        }
        SqlToken::StringLiteral(value) => Some((quote_sql_string(value), 1)),
        SqlToken::Symbol(sign @ ('-' | '+')) => match tokens.get(cursor + 1) {
            Some(SqlToken::Word(value)) if value.bytes().all(|byte| byte.is_ascii_digit()) => {
                Some((format!("{sign}{value}"), 2))
            }
            _ => None,
        },
        _ => None,
    }
}

fn quote_sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn canonical_declared_type(value: &str) -> String {
    if matches_ignore_ascii_case(value, &["integer", "text", "real", "blob"]) {
        value.to_ascii_uppercase()
    } else {
        value.to_string()
    }
}

fn canonical_type_word(value: &str) -> bool {
    canonical_ascii_identifier(value)
        && !matches_ignore_ascii_case(
            value,
            &[
                "add",
                "alter",
                "as",
                "check",
                "collate",
                "constraint",
                "default",
                "generated",
                "not",
                "null",
                "primary",
                "references",
                "unique",
            ],
        )
}

fn canonical_unquoted_identifier(token: Option<&SqlToken>) -> Option<String> {
    let value = word_identifier(token)?;
    canonical_ascii_identifier(value).then(|| value.to_string())
}

fn word_identifier(token: Option<&SqlToken>) -> Option<&str> {
    match token? {
        SqlToken::Word(value) => Some(value),
        SqlToken::Identifier(_) | SqlToken::StringLiteral(_) | SqlToken::Symbol(_) => None,
    }
}

fn canonical_ascii_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 128
        && matches!(bytes.next(), Some(byte) if byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn token_is_word(token: Option<&SqlToken>, value: &str) -> bool {
    matches!(token, Some(SqlToken::Word(word)) if word.eq_ignore_ascii_case(value))
}

fn matches_ignore_ascii_case(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

pub(crate) fn validate_additive_transitions(
    plan: &AdditiveManifestPlan,
    states: &[D1MigrationStateExpectation],
) -> Result<(), AdditiveContractError> {
    if states.len() != plan.prefixes.len() + 1 {
        return Err(AdditiveContractError::transition(
            "d1.migration_reconciliation_additive_prefix_mismatch",
            "the additive transition plan must bind every expected manifest prefix including baseline",
        ));
    }
    for (index, prefix) in plan.prefixes.iter().enumerate() {
        validate_prefix_transition(&states[index], &states[index + 1], prefix)?;
    }
    Ok(())
}

fn validate_prefix_transition(
    previous: &D1MigrationStateExpectation,
    current: &D1MigrationStateExpectation,
    plan: &AdditivePrefixPlan,
) -> Result<(), AdditiveContractError> {
    let previous_objects = previous
        .schema_objects
        .iter()
        .map(|object| ((object.object_type.as_str(), object.name.as_str()), object))
        .collect::<BTreeMap<_, _>>();
    let current_objects = current
        .schema_objects
        .iter()
        .map(|object| ((object.object_type.as_str(), object.name.as_str()), object))
        .collect::<BTreeMap<_, _>>();
    let addition_target = plan
        .addition
        .as_ref()
        .map(|effect| effect.table_name.as_str());

    for (identity, object) in &previous_objects {
        let successor = current_objects.get(identity).ok_or_else(|| {
            AdditiveContractError::transition(
                "d1.migration_reconciliation_additive_schema_drift",
                "an existing schema object disappeared or changed identity across an additive prefix",
            )
        })?;
        if object.object_type == "table" && addition_target == Some(object.name.as_str()) {
            if successor.table_name != object.table_name
                || successor.sql_sha256 == object.sql_sha256
            {
                return Err(AdditiveContractError::transition(
                    "d1.migration_reconciliation_additive_parent_sql_drift",
                    "an altered parent must retain exact table identity and receive a distinct reviewed sqlite_master SQL digest",
                ));
            }
        } else if *successor != *object {
            return Err(AdditiveContractError::transition(
                "d1.migration_reconciliation_additive_schema_drift",
                "schema objects outside the exact additive target and newly created set must remain byte-identical",
            ));
        }
    }
    for ((object_type, name), _) in current_objects
        .iter()
        .filter(|(identity, _)| !previous_objects.contains_key(identity))
    {
        if !plan
            .created_objects
            .contains(&(object_type.to_string(), name.to_string()))
        {
            return Err(AdditiveContractError::transition(
                "d1.migration_reconciliation_additive_schema_drift",
                "an additive prefix introduced a schema object not classified as CREATE intent",
            ));
        }
    }

    let previous_tables = previous
        .tables
        .iter()
        .map(|table| (table.name.as_str(), table))
        .collect::<BTreeMap<_, _>>();
    let current_tables = current
        .tables
        .iter()
        .map(|table| (table.name.as_str(), table))
        .collect::<BTreeMap<_, _>>();
    for (name, table) in &previous_tables {
        let successor = current_tables.get(name).ok_or_else(|| {
            AdditiveContractError::transition(
                "d1.migration_reconciliation_additive_parent_missing",
                "every baseline or created table must remain present through later additive prefixes",
            )
        })?;
        if addition_target == Some(*name) {
            validate_column_append(table, successor, plan.addition.as_ref().expect("target"))?;
        } else if *successor != *table {
            return Err(AdditiveContractError::transition(
                "d1.migration_reconciliation_additive_table_drift",
                "tables outside the exact additive target must retain complete ordered xinfo and foreign-key expectations",
            ));
        }
    }
    let created_tables = plan
        .created_objects
        .iter()
        .filter_map(|(object_type, name)| (object_type == "table").then_some(name.as_str()))
        .collect::<BTreeSet<_>>();
    for name in current_tables
        .keys()
        .filter(|name| !previous_tables.contains_key(*name))
    {
        if !created_tables.contains(name) {
            return Err(AdditiveContractError::transition(
                "d1.migration_reconciliation_additive_table_drift",
                "a table expectation appeared without exact CREATE intent in that prefix",
            ));
        }
    }
    if let Some(target) = addition_target {
        if !previous_tables.contains_key(target) || !current_tables.contains_key(target) {
            return Err(AdditiveContractError::transition(
                "d1.migration_reconciliation_additive_parent_missing",
                "ALTER TABLE ADD COLUMN requires the exact parent and its complete baseline expectation before the additive prefix",
            ));
        }
    }
    Ok(())
}

fn validate_column_append(
    previous: &crate::d1_migration_reconciliation::D1MigrationTableExpectation,
    current: &crate::d1_migration_reconciliation::D1MigrationTableExpectation,
    effect: &AddColumnEffect,
) -> Result<(), AdditiveContractError> {
    if previous.foreign_keys != current.foreign_keys
        || current.columns.len() != previous.columns.len() + 1
        || current.columns[..previous.columns.len()] != previous.columns
    {
        return Err(AdditiveContractError::transition(
            "d1.migration_reconciliation_additive_column_drift",
            "an additive prefix must preserve every prior ordered column and foreign key before appending exactly one column",
        ));
    }
    let expected_cid = previous
        .columns
        .last()
        .and_then(|column| column.cid.checked_add(1))
        .unwrap_or(0);
    let mut expected = effect.column.clone();
    expected.cid = expected_cid;
    if current.columns.last() != Some(&expected) {
        return Err(AdditiveContractError::transition(
            "d1.migration_reconciliation_additive_column_drift",
            "the appended column must match the classified name, declared type, nullability, default, key position, hidden flag, and next cid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::d1_migration_reconciliation::{
        D1MigrationForeignKeyExpectation, D1MigrationSchemaObjectExpectation,
        D1MigrationTableExpectation,
    };

    fn words(values: &[&str]) -> Vec<SqlToken> {
        values
            .iter()
            .map(|value| SqlToken::Word((*value).to_string()))
            .collect()
    }

    fn column(cid: i64, name: &str, declared_type: &str) -> D1MigrationColumnExpectation {
        D1MigrationColumnExpectation {
            cid,
            name: name.to_string(),
            declared_type: declared_type.to_string(),
            not_null: false,
            default_value: None,
            primary_key_position: i64::from(cid == 0),
            hidden: 0,
        }
    }

    fn table_state(
        prefix: usize,
        sql: &str,
        columns: Vec<D1MigrationColumnExpectation>,
    ) -> D1MigrationStateExpectation {
        D1MigrationStateExpectation {
            manifest_prefix_length: prefix,
            schema_objects: vec![D1MigrationSchemaObjectExpectation {
                object_type: "table".to_string(),
                name: "items".to_string(),
                table_name: "items".to_string(),
                sql_sha256: sql.to_string(),
            }],
            tables: vec![D1MigrationTableExpectation {
                name: "items".to_string(),
                columns,
                foreign_keys: Vec::new(),
            }],
        }
    }

    #[test]
    fn closed_grammar_accepts_one_column_and_exact_pragma() {
        let add = classify_additive_statement(&words(&[
            "ALTER", "TABLE", "items", "ADD", "COLUMN", "status", "TEXT",
        ]))
        .expect("classified add")
        .expect("add effect");
        assert_eq!(
            add,
            AdditiveStatement::AddColumn(AddColumnEffect {
                table_name: "items".to_string(),
                column: D1MigrationColumnExpectation {
                    cid: -1,
                    name: "status".to_string(),
                    declared_type: "TEXT".to_string(),
                    not_null: false,
                    default_value: None,
                    primary_key_position: 0,
                    hidden: 0,
                },
            })
        );
        assert_eq!(
            classify_additive_statement(&[
                SqlToken::Word("PRAGMA".to_string()),
                SqlToken::Word("foreign_keys".to_string()),
                SqlToken::Symbol('='),
                SqlToken::Word("ON".to_string()),
            ])
            .expect("classified pragma"),
            Some(AdditiveStatement::ForeignKeysOn),
        );

        let bounded_defaults = [
            (
                vec![
                    SqlToken::Word("ALTER".to_string()),
                    SqlToken::Word("TABLE".to_string()),
                    SqlToken::Word("items".to_string()),
                    SqlToken::Word("ADD".to_string()),
                    SqlToken::Word("label".to_string()),
                    SqlToken::Word("TEXT".to_string()),
                    SqlToken::Word("DEFAULT".to_string()),
                    SqlToken::StringLiteral("reader's choice".to_string()),
                ],
                "'reader''s choice'",
            ),
            (
                vec![
                    SqlToken::Word("ALTER".to_string()),
                    SqlToken::Word("TABLE".to_string()),
                    SqlToken::Word("items".to_string()),
                    SqlToken::Word("ADD".to_string()),
                    SqlToken::Word("rank".to_string()),
                    SqlToken::Word("INTEGER".to_string()),
                    SqlToken::Word("DEFAULT".to_string()),
                    SqlToken::Symbol('-'),
                    SqlToken::Word("1".to_string()),
                ],
                "-1",
            ),
        ];
        for (tokens, expected_default) in bounded_defaults {
            let Some(AdditiveStatement::AddColumn(effect)) =
                classify_additive_statement(&tokens).expect("bounded default")
            else {
                panic!("expected ADD COLUMN classification");
            };
            assert_eq!(
                effect.column.default_value.as_deref(),
                Some(expected_default)
            );
        }
    }

    #[test]
    fn closed_grammar_rejects_non_allowlisted_alter_and_pragma_forms() {
        let rejected = [
            words(&["ALTER", "TABLE", "items", "RENAME", "TO", "other"]),
            words(&["ALTER", "TABLE", "items", "DROP", "COLUMN", "status"]),
            words(&["ALTER", "TABLE", "items", "ADD", "status", "TEXT", "UNIQUE"]),
            words(&[
                "ALTER", "TABLE", "items", "ADD", "status", "TEXT", "NOT", "NULL", "DEFAULT",
                "NULL",
            ]),
            vec![
                SqlToken::Word("ALTER".to_string()),
                SqlToken::Word("TABLE".to_string()),
                SqlToken::Word("main".to_string()),
                SqlToken::Symbol('.'),
                SqlToken::Word("items".to_string()),
                SqlToken::Word("ADD".to_string()),
                SqlToken::Word("status".to_string()),
                SqlToken::Word("TEXT".to_string()),
            ],
            words(&["PRAGMA", "foreign_keys", "ON"]),
            words(&["PRAGMA", "journal_mode", "ON"]),
        ];
        for tokens in rejected {
            assert!(classify_additive_statement(&tokens).is_err(), "{tokens:?}");
        }
    }

    #[test]
    fn transition_requires_exact_single_appended_column_and_sql_change() {
        let baseline = table_state(0, &"a".repeat(64), vec![column(0, "id", "INTEGER")]);
        let mut added = column(1, "status", "TEXT");
        added.primary_key_position = 0;
        let current = table_state(
            1,
            &"b".repeat(64),
            vec![column(0, "id", "INTEGER"), added.clone()],
        );
        let plan = AdditiveManifestPlan {
            prefixes: vec![AdditivePrefixPlan {
                created_objects: BTreeSet::new(),
                addition: Some(AddColumnEffect {
                    table_name: "items".to_string(),
                    column: D1MigrationColumnExpectation {
                        cid: -1,
                        ..added.clone()
                    },
                }),
                foreign_keys_on: true,
            }],
        };
        validate_additive_transitions(&plan, &[baseline.clone(), current.clone()])
            .expect("exact append");

        let mut malformed_states = Vec::new();

        let mut reordered = current.clone();
        reordered.tables[0].columns.swap(0, 1);
        malformed_states.push(reordered);

        let mut missing = current.clone();
        missing.tables[0].columns.pop();
        malformed_states.push(missing);

        let mut extra = current.clone();
        extra.tables[0].columns.push(column(2, "extra", "TEXT"));
        malformed_states.push(extra);

        let mut prior_drift = current.clone();
        prior_drift.tables[0].columns[0].name = "changed_id".to_string();
        malformed_states.push(prior_drift);

        let mutations: [fn(&mut D1MigrationColumnExpectation); 7] = [
            |column: &mut D1MigrationColumnExpectation| column.cid = 7,
            |column: &mut D1MigrationColumnExpectation| column.name = "other".to_string(),
            |column: &mut D1MigrationColumnExpectation| {
                column.declared_type = "INTEGER".to_string()
            },
            |column: &mut D1MigrationColumnExpectation| column.not_null = true,
            |column: &mut D1MigrationColumnExpectation| {
                column.default_value = Some("'other'".to_string())
            },
            |column: &mut D1MigrationColumnExpectation| column.primary_key_position = 1,
            |column: &mut D1MigrationColumnExpectation| column.hidden = 1,
        ];
        for mutate in mutations {
            let mut drifted = current.clone();
            mutate(&mut drifted.tables[0].columns[1]);
            malformed_states.push(drifted);
        }

        let mut foreign_key_drift = current.clone();
        foreign_key_drift.tables[0]
            .foreign_keys
            .push(D1MigrationForeignKeyExpectation {
                id: 0,
                sequence: 0,
                referenced_table: "parent".to_string(),
                from_column: "status".to_string(),
                to_column: Some("id".to_string()),
                on_update: "NO ACTION".to_string(),
                on_delete: "NO ACTION".to_string(),
                match_mode: "NONE".to_string(),
            });
        malformed_states.push(foreign_key_drift);

        for state in malformed_states {
            let error = validate_additive_transitions(&plan, &[baseline.clone(), state])
                .expect_err("any column/FK drift must fail closed");
            assert_eq!(
                error.code,
                "d1.migration_reconciliation_additive_column_drift"
            );
        }

        let mut unchanged_sql = current.clone();
        unchanged_sql.schema_objects[0].sql_sha256 = "a".repeat(64);
        assert_eq!(
            validate_additive_transitions(&plan, &[baseline.clone(), unchanged_sql])
                .expect_err("sqlite_master digest must change")
                .code,
            "d1.migration_reconciliation_additive_parent_sql_drift"
        );

        let mut missing_parent = current;
        missing_parent.tables.clear();
        assert_eq!(
            validate_additive_transitions(&plan, &[baseline, missing_parent])
                .expect_err("physical parent must remain present")
                .code,
            "d1.migration_reconciliation_additive_parent_missing"
        );
    }
}
