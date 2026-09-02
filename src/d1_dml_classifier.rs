//! Conservative exact D1 DML statement classification.
//!
//! This is deliberately a closed lexical recognizer, not a general SQL parser.
//! It accepts one bounded statement whose target is one unquoted canonical
//! lowercase relation identity and rejects comments, quoted identifiers,
//! qualified targets, CTEs, and unrecognized compound forms.

use serde::Serialize;

use crate::d1_execute_write::D1WriteStatementKind;
use crate::d1_reserved_relation_graph::D1WriteOperationForm;

const MAX_SQL_BYTES: usize = 1024 * 1024;
const MAX_SQL_TOKENS: usize = 65_536;
const MAX_PARENTHESIS_DEPTH: usize = 256;
const MAX_RELATION_BYTES: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1ClassifiedDml {
    pub(crate) statement_kind: D1WriteStatementKind,
    pub(crate) form: D1WriteOperationForm,
    pub(crate) relation: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum D1DmlClassifierClassification {
    Empty,
    TooLarge,
    TokenLimitExceeded,
    MultipleStatements,
    CommentOrQuotedIdentityUnsupported,
    LexicalStructureUnsupported,
    UnsupportedStatement,
    TargetMissing,
    TargetInvalid,
    CompoundFormUnsupported,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct D1DmlClassifierError {
    pub(crate) code: &'static str,
    pub(crate) classification: D1DmlClassifierClassification,
    pub(crate) message: &'static str,
}

pub(crate) fn classify_d1_dml(sql: &str) -> Result<D1ClassifiedDml, D1DmlClassifierError> {
    if sql.is_empty() || sql.trim().is_empty() {
        return Err(error(
            D1DmlClassifierClassification::Empty,
            "D1 DML SQL was empty",
        ));
    }
    if sql.len() > MAX_SQL_BYTES {
        return Err(error(
            D1DmlClassifierClassification::TooLarge,
            "D1 DML SQL exceeded the exact classifier byte cap",
        ));
    }
    if sql.contains("--")
        || sql.contains("/*")
        || sql.contains("*/")
        || sql.contains('"')
        || sql.contains('`')
        || sql.contains('[')
        || sql.contains(']')
    {
        return Err(error(
            D1DmlClassifierClassification::CommentOrQuotedIdentityUnsupported,
            "comments and quoted identifiers are outside the closed D1 DML contract",
        ));
    }
    let trimmed = sql.trim();
    let body = trimmed.strip_suffix(';').unwrap_or(trimmed).trim_end();
    if body.contains(';') {
        return Err(error(
            D1DmlClassifierClassification::MultipleStatements,
            "exactly one D1 DML statement is required",
        ));
    }
    let tokens = tokenize_sql(body)?;
    validate_parentheses(&tokens)?;
    let (kind, form, relation_index) = if word_is(body, &tokens, 0, b"INSERT") {
        if word_is(body, &tokens, 1, b"OR") {
            if word_is(body, &tokens, 2, b"REPLACE") && word_is(body, &tokens, 3, b"INTO") {
                reject_wrapper_compound_suffix(body, &tokens)?;
                Ok((
                    D1WriteStatementKind::Insert,
                    D1WriteOperationForm::InsertOrReplace,
                    4,
                ))
            } else {
                Err(error(
                    D1DmlClassifierClassification::CompoundFormUnsupported,
                    "INSERT form was outside the closed D1 DML contract",
                ))
            }
        } else if word_is(body, &tokens, 1, b"INTO") {
            classify_insert_form(body, &tokens).map(|form| (D1WriteStatementKind::Insert, form, 2))
        } else {
            Err(error(
                D1DmlClassifierClassification::CompoundFormUnsupported,
                "INSERT form was outside the closed D1 DML contract",
            ))
        }
    } else if word_is(body, &tokens, 0, b"REPLACE") {
        if word_is(body, &tokens, 1, b"INTO") {
            reject_wrapper_compound_suffix(body, &tokens)?;
            Ok((
                D1WriteStatementKind::Replace,
                D1WriteOperationForm::Replace,
                2,
            ))
        } else {
            Err(error(
                D1DmlClassifierClassification::CompoundFormUnsupported,
                "DML form was outside the closed contract",
            ))
        }
    } else if word_is(body, &tokens, 0, b"UPDATE") {
        if word_is(body, &tokens, 1, b"OR") {
            if word_is(body, &tokens, 2, b"REPLACE") {
                Ok((
                    D1WriteStatementKind::Update,
                    D1WriteOperationForm::UpdateOrReplace,
                    3,
                ))
            } else {
                Err(error(
                    D1DmlClassifierClassification::CompoundFormUnsupported,
                    "UPDATE conflict form was outside the closed D1 DML contract",
                ))
            }
        } else {
            Ok((
                D1WriteStatementKind::Update,
                D1WriteOperationForm::Update,
                1,
            ))
        }
    } else if word_is(body, &tokens, 0, b"DELETE") {
        if word_is(body, &tokens, 1, b"FROM") {
            Ok((
                D1WriteStatementKind::Delete,
                D1WriteOperationForm::Delete,
                2,
            ))
        } else {
            Err(error(
                D1DmlClassifierClassification::CompoundFormUnsupported,
                "DML form was outside the closed contract",
            ))
        }
    } else {
        Err(error(
            D1DmlClassifierClassification::UnsupportedStatement,
            "D1 write SQL must be one supported INSERT, UPDATE, DELETE, or REPLACE form",
        ))
    }?;
    let raw = tokens.get(relation_index).ok_or_else(|| {
        error(
            D1DmlClassifierClassification::TargetMissing,
            "D1 DML target relation was absent",
        )
    })?;
    if raw.kind != D1SqlTokenKind::Word {
        return Err(error(
            D1DmlClassifierClassification::TargetInvalid,
            "D1 DML target was not one canonical lowercase unqualified relation",
        ));
    }
    let relation = std::str::from_utf8(&body.as_bytes()[raw.start..raw.end]).map_err(|_| {
        error(
            D1DmlClassifierClassification::TargetInvalid,
            "D1 DML target was not one canonical lowercase unqualified relation",
        )
    })?;
    if !valid_relation(relation) {
        return Err(error(
            D1DmlClassifierClassification::TargetInvalid,
            "D1 DML target was not one canonical lowercase unqualified relation",
        ));
    }
    if symbol_is(&tokens, relation_index + 1, b'.')
        || (symbol_is(&tokens, relation_index + 1, b'(')
            && !matches!(
                kind,
                D1WriteStatementKind::Insert | D1WriteStatementKind::Replace
            ))
    {
        return Err(error(
            D1DmlClassifierClassification::TargetInvalid,
            "D1 DML target relation used unsupported attached syntax",
        ));
    }
    Ok(D1ClassifiedDml {
        statement_kind: kind,
        form,
        relation: relation.to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum D1SqlTokenKind {
    Word,
    StringLiteral,
    Symbol(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct D1SqlToken {
    kind: D1SqlTokenKind,
    start: usize,
    end: usize,
}

fn tokenize_sql(sql: &str) -> Result<Vec<D1SqlToken>, D1DmlClassifierError> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let start = index;
        let kind = if bytes[index] == b'\'' {
            index += 1;
            let mut closed = false;
            while index < bytes.len() {
                if bytes[index] == b'\'' {
                    if bytes.get(index + 1) == Some(&b'\'') {
                        index += 2;
                    } else {
                        index += 1;
                        closed = true;
                        break;
                    }
                } else {
                    index += 1;
                }
            }
            if !closed {
                return Err(error(
                    D1DmlClassifierClassification::LexicalStructureUnsupported,
                    "D1 DML SQL contained an unterminated string literal",
                ));
            }
            D1SqlTokenKind::StringLiteral
        } else if bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_' {
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b'$')
            {
                index += 1;
            }
            D1SqlTokenKind::Word
        } else if bytes[index].is_ascii_punctuation() {
            index += 1;
            D1SqlTokenKind::Symbol(bytes[start])
        } else {
            return Err(error(
                D1DmlClassifierClassification::LexicalStructureUnsupported,
                "D1 DML SQL contained unsupported non-ASCII syntax outside a string literal",
            ));
        };
        if tokens.len() == MAX_SQL_TOKENS {
            return Err(error(
                D1DmlClassifierClassification::TokenLimitExceeded,
                "D1 DML SQL exceeded the exact lexical token cap",
            ));
        }
        tokens.push(D1SqlToken {
            kind,
            start,
            end: index,
        });
    }
    if tokens.is_empty() {
        return Err(error(
            D1DmlClassifierClassification::Empty,
            "D1 DML SQL was empty",
        ));
    }
    Ok(tokens)
}

fn validate_parentheses(tokens: &[D1SqlToken]) -> Result<(), D1DmlClassifierError> {
    let mut depth = 0usize;
    for token in tokens {
        match token.kind {
            D1SqlTokenKind::Symbol(b'(') => {
                depth = depth.checked_add(1).ok_or_else(|| {
                    error(
                        D1DmlClassifierClassification::LexicalStructureUnsupported,
                        "D1 DML SQL parenthesis depth was invalid",
                    )
                })?;
                if depth > MAX_PARENTHESIS_DEPTH {
                    return Err(error(
                        D1DmlClassifierClassification::LexicalStructureUnsupported,
                        "D1 DML SQL exceeded the exact parenthesis-depth cap",
                    ));
                }
            }
            D1SqlTokenKind::Symbol(b')') => {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    error(
                        D1DmlClassifierClassification::LexicalStructureUnsupported,
                        "D1 DML SQL contained an unmatched closing parenthesis",
                    )
                })?;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(error(
            D1DmlClassifierClassification::LexicalStructureUnsupported,
            "D1 DML SQL contained an unmatched opening parenthesis",
        ));
    }
    Ok(())
}

fn classify_insert_form(
    sql: &str,
    tokens: &[D1SqlToken],
) -> Result<D1WriteOperationForm, D1DmlClassifierError> {
    let mut depth = 0usize;
    let mut conflict = None;
    let mut action = None;
    let mut ambiguous = false;
    for (index, token) in tokens.iter().enumerate() {
        match token.kind {
            D1SqlTokenKind::Symbol(b'(') => depth += 1,
            D1SqlTokenKind::Symbol(b')') => depth -= 1,
            D1SqlTokenKind::Word if depth == 0 => {
                if word_is(sql, tokens, index, b"ON")
                    && word_is(sql, tokens, index + 1, b"CONFLICT")
                {
                    if conflict.replace(index).is_some() {
                        ambiguous = true;
                    }
                }
                if word_is(sql, tokens, index, b"DO")
                    && (word_is(sql, tokens, index + 1, b"UPDATE")
                        || word_is(sql, tokens, index + 1, b"NOTHING"))
                {
                    if action.replace(index).is_some() {
                        ambiguous = true;
                    }
                }
            }
            _ => {}
        }
    }
    match (conflict, action, ambiguous) {
        (None, None, false) => Ok(D1WriteOperationForm::Insert),
        (Some(conflict), Some(action), false) if action > conflict => {
            if word_is(sql, tokens, action + 1, b"NOTHING") {
                return Err(error(
                    D1DmlClassifierClassification::CompoundFormUnsupported,
                    "ON CONFLICT DO NOTHING is outside the closed D1 DML contract",
                ));
            }
            if !word_is(sql, tokens, action + 1, b"UPDATE")
                || !word_is(sql, tokens, action + 2, b"SET")
                || tokens.get(action + 3).is_none()
            {
                return Err(error(
                    D1DmlClassifierClassification::CompoundFormUnsupported,
                    "ON CONFLICT DO UPDATE was truncated or outside the closed D1 DML contract",
                ));
            }
            Ok(D1WriteOperationForm::UpsertDoUpdate)
        }
        _ => Err(error(
            D1DmlClassifierClassification::CompoundFormUnsupported,
            "ON CONFLICT action was absent, duplicated, reordered, or ambiguous",
        )),
    }
}

fn reject_wrapper_compound_suffix(
    sql: &str,
    tokens: &[D1SqlToken],
) -> Result<(), D1DmlClassifierError> {
    match classify_insert_form(sql, tokens)? {
        D1WriteOperationForm::Insert => Ok(()),
        D1WriteOperationForm::UpsertDoUpdate => Err(error(
            D1DmlClassifierClassification::CompoundFormUnsupported,
            "replacement wrappers cannot carry an ON CONFLICT action in the closed D1 DML contract",
        )),
        _ => unreachable!("insert compound recognizer returns only insert or upsert"),
    }
}

fn word_is(sql: &str, tokens: &[D1SqlToken], index: usize, expected: &[u8]) -> bool {
    tokens.get(index).is_some_and(|token| {
        token.kind == D1SqlTokenKind::Word
            && sql.as_bytes()[token.start..token.end].eq_ignore_ascii_case(expected)
    })
}

fn symbol_is(tokens: &[D1SqlToken], index: usize, expected: u8) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.kind == D1SqlTokenKind::Symbol(expected))
}

fn valid_relation(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_RELATION_BYTES
        && !value.contains('.')
        && value.to_ascii_lowercase() == value
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'_' | b'$')
        })
}

fn error(
    classification: D1DmlClassifierClassification,
    message: &'static str,
) -> D1DmlClassifierError {
    D1DmlClassifierError {
        code: "d1.execute_write_classifier_denied",
        classification,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_closed_forms_and_relations() {
        let cases = [
            (
                "INSERT INTO stories(id) VALUES (?)",
                D1WriteOperationForm::Insert,
                "stories",
            ),
            (
                "INSERT OR REPLACE INTO stories (id) VALUES (?)",
                D1WriteOperationForm::InsertOrReplace,
                "stories",
            ),
            (
                "INSERT INTO stories(id) VALUES (?) ON CONFLICT(id) DO UPDATE SET id=?",
                D1WriteOperationForm::UpsertDoUpdate,
                "stories",
            ),
            (
                "UPDATE OR REPLACE stories SET id=?",
                D1WriteOperationForm::UpdateOrReplace,
                "stories",
            ),
            (
                "DELETE FROM stories WHERE id=?",
                D1WriteOperationForm::Delete,
                "stories",
            ),
            (
                "REPLACE INTO stories(id) VALUES (?)",
                D1WriteOperationForm::Replace,
                "stories",
            ),
        ];
        for (sql, form, relation) in cases {
            let classified = classify_d1_dml(sql).expect(sql);
            assert_eq!(classified.form, form);
            assert_eq!(classified.relation, relation);
        }
    }

    #[test]
    fn lexical_upsert_exposes_update_primitive_for_reserved_on_update_cascade() {
        use crate::d1_reserved_relation_graph::{
            D1RelationWriteOperation, required_relation_write_operations,
        };

        let sql = "iNsErT\tInTo parents(id) VALUES (?)\n  oN\r\nCoNfLiCt(id)\tDo\nUpDaTe\tSeT id=?";
        let classified = classify_d1_dml(sql).expect("lexical UPSERT");
        assert_eq!(classified.statement_kind, D1WriteStatementKind::Insert);
        assert_eq!(classified.form, D1WriteOperationForm::UpsertDoUpdate);
        assert_eq!(classified.relation, "parents");
        assert_eq!(
            required_relation_write_operations(classified.form).expect("closed primitive set"),
            &[
                D1RelationWriteOperation::Insert,
                D1RelationWriteOperation::Update,
            ],
            "the update primitive must reach reserved-relation graph authority, including ON UPDATE CASCADE edges"
        );
    }

    #[test]
    fn replacement_wrappers_reject_every_compound_suffix_product() {
        let suffixes = [
            "ON CONFLICT(id) DO UPDATE SET id=?",
            "ON CONFLICT(id) DO NOTHING",
            "ON CONFLICT(id)",
            "ON CONFLICT(id) DO",
            "ON CONFLICT(id) DO UPDATE",
            "ON CONFLICT(id) DO UPDATE SET",
            "DO UPDATE SET id=?",
            "DO NOTHING",
            "DO UPDATE SET id=? ON CONFLICT(id)",
            "ON CONFLICT(id) DO UPDATE SET id=? ON CONFLICT(id) DO UPDATE SET id=?",
            "ON CONFLICT(id) DO UPDATE SET id=? ON CONFLICT(id) DO NOTHING",
        ];
        for wrapper in [
            "INSERT OR REPLACE INTO parents(id) VALUES (?)",
            "REPLACE INTO parents(id) VALUES (?)",
        ] {
            for suffix in suffixes {
                let sql = format!("{wrapper} {suffix}");
                assert_eq!(
                    classify_d1_dml(&sql)
                        .expect_err("replacement wrapper compound suffix must deny")
                        .classification,
                    D1DmlClassifierClassification::CompoundFormUnsupported,
                    "{sql}"
                );
            }
        }
    }

    #[test]
    fn dollar_is_an_exact_unquoted_relation_continuation_across_write_forms() {
        let cases = [
            (
                "INSERT INTO safe$protected(id) VALUES ($id)",
                D1WriteOperationForm::Insert,
            ),
            (
                "INSERT OR REPLACE INTO safe$protected(id) VALUES (?)",
                D1WriteOperationForm::InsertOrReplace,
            ),
            (
                "REPLACE INTO safe$protected(id) VALUES (?)",
                D1WriteOperationForm::Replace,
            ),
            (
                "UPDATE safe$protected SET id=?",
                D1WriteOperationForm::Update,
            ),
            (
                "UPDATE OR REPLACE safe$protected SET id=?",
                D1WriteOperationForm::UpdateOrReplace,
            ),
            (
                "DELETE FROM safe$protected WHERE id=?",
                D1WriteOperationForm::Delete,
            ),
        ];
        for (sql, form) in cases {
            let classified = classify_d1_dml(sql).expect(sql);
            assert_eq!(classified.relation, "safe$protected", "{sql}");
            assert_eq!(classified.form, form, "{sql}");
        }

        for sql in [
            "UPDATE $safe SET id=?",
            "INSERT INTO $safe(id) VALUES (?)",
            "DELETE FROM $safe WHERE id=?",
            "UPDATE main.safe$protected SET id=?",
            "UPDATE safe$protected.extra SET id=?",
        ] {
            assert_eq!(
                classify_d1_dml(sql)
                    .expect_err("dollar cannot begin a closed relation identity")
                    .classification,
                D1DmlClassifierClassification::TargetInvalid,
                "{sql}"
            );
        }
        assert_eq!(
            classify_d1_dml("UPDATE \"safe$protected\" SET id=?")
                .expect_err("quoted dollar-bearing relation remains unsupported")
                .classification,
            D1DmlClassifierClassification::CommentOrQuotedIdentityUnsupported
        );
    }

    #[test]
    fn keyword_like_string_content_does_not_create_compound_authority() {
        let classified = classify_d1_dml(
            "INSERT INTO reserved_child(note) VALUES ('ON CONFLICT DO UPDATE SET parent_id=1, ON UPDATE CASCADE')",
        )
        .expect("string content is not SQL keyword authority");
        assert_eq!(classified.form, D1WriteOperationForm::Insert);
        assert_eq!(classified.relation, "reserved_child");
    }

    #[test]
    fn comments_remain_outside_the_closed_classifier_contract() {
        for sql in [
            "INSERT INTO stories(id) VALUES (?) ON/* bounded */CONFLICT(id) DO UPDATE SET id=?",
            "INSERT INTO stories(id) VALUES (?) ON CONFLICT(id) -- action\nDO UPDATE SET id=?",
            "INSERT INTO stories(id) VALUES ('comment -- marker')",
        ] {
            assert_eq!(
                classify_d1_dml(sql)
                    .expect_err("comments remain unsupported")
                    .classification,
                D1DmlClassifierClassification::CommentOrQuotedIdentityUnsupported,
                "{sql}"
            );
        }
    }

    #[test]
    fn truncated_ambiguous_and_do_nothing_compounds_fail_closed() {
        for sql in [
            "INSERT INTO stories(id) VALUES (?) ON CONFLICT(id)",
            "INSERT INTO stories(id) VALUES (?) ON CONFLICT(id) DO",
            "INSERT INTO stories(id) VALUES (?) ON CONFLICT(id) DO UPDATE",
            "INSERT INTO stories(id) VALUES (?) ON CONFLICT(id) DO UPDATE SET",
            "INSERT INTO stories(id) VALUES (?) ON CONFLICT(id) DO NOTHING",
            "INSERT INTO stories(id) VALUES (?) DO UPDATE SET id=?",
            "INSERT INTO stories(id) VALUES (?) ON CONFLICT(id) DO UPDATE SET id=? ON CONFLICT(id) DO UPDATE SET id=?",
            "INSERT OR IGNORE INTO stories(id) VALUES (?)",
        ] {
            assert_eq!(
                classify_d1_dml(sql)
                    .expect_err("unsupported compound must deny")
                    .classification,
                D1DmlClassifierClassification::CompoundFormUnsupported,
                "{sql}"
            );
        }
    }

    #[test]
    fn malformed_or_excessive_lexical_structure_fails_closed() {
        for sql in [
            "INSERT INTO stories(id VALUES (?)",
            "INSERT INTO stories(id)) VALUES (?)",
            "INSERT INTO stories(note) VALUES ('unterminated)",
        ] {
            assert_eq!(
                classify_d1_dml(sql)
                    .expect_err("malformed lexical structure must deny")
                    .classification,
                D1DmlClassifierClassification::LexicalStructureUnsupported,
                "{sql}"
            );
        }

        let token_exhaustion = format!(
            "INSERT INTO stories(id) VALUES ({})",
            "?,".repeat(MAX_SQL_TOKENS)
        );
        assert_eq!(
            classify_d1_dml(&token_exhaustion)
                .expect_err("bounded token stream must deny exhaustion")
                .classification,
            D1DmlClassifierClassification::TokenLimitExceeded
        );
    }

    #[test]
    fn denies_ambiguous_or_noncanonical_targets() {
        for sql in [
            "WITH x AS (SELECT 1) UPDATE stories SET id=1",
            "UPDATE main.stories SET id=1",
            "UPDATE Stories SET id=1",
            "UPDATE \"stories\" SET id=1",
            "UPDATE stories SET id=1; DELETE FROM stories",
        ] {
            assert!(classify_d1_dml(sql).is_err(), "{sql}");
        }
    }
}
